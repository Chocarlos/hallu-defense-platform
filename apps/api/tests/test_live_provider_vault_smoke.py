from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from hallu_defense.services.providers import JsonTransport
from hallu_defense.services.secrets import SecretNotFoundError, SecretValue
from scripts.dev import live_provider_vault_smoke as smoke


class TrackingSecretManager:
    def __init__(self, value: str | None) -> None:
        self.value = value
        self.names: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.names.append(name)
        if field != "value" or self.value is None:
            raise SecretNotFoundError(name)
        return SecretValue(name=name, _value=self.value)


class RecordingTransport(JsonTransport):
    def __init__(self, response: Mapping[str, object]) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, object],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "payload": dict(payload),
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.response


def _config(**overrides: object) -> smoke.LiveProviderVaultSmokeConfig:
    values: dict[str, object] = {
        "vault_addr": "http://127.0.0.1:8200",
        "vault_mount": "secret",
        "vault_token_env": "TEST_VAULT_TOKEN",
        "vault_token_value": "vault-token-value",
        "vault_timeout_seconds": 3,
        "openai_base_url": "http://127.0.0.1:11434/v1",
        "ollama_base_url": "http://127.0.0.1:11434",
        "model": "local-smoke-model",
        "provider_timeout_seconds": 9,
    }
    values.update(overrides)
    return smoke.LiveProviderVaultSmokeConfig(**values)  # type: ignore[arg-type]


def test_provider_vault_smoke_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert result["redacted"] is True


def test_provider_vault_smoke_exercises_vault_openai_and_ollama_without_leaks() -> None:
    credential = "vault-provider-secret"
    openai_text = "sensitive openai response"
    ollama_text = "sensitive ollama response"
    manager = TrackingSecretManager(credential)
    openai_transport = RecordingTransport(
        {
            "model": "local-smoke-model",
            "choices": [{"message": {"content": openai_text}}],
        }
    )
    ollama_transport = RecordingTransport(
        {
            "model": "local-smoke-model",
            "message": {"content": ollama_text},
            "done": True,
        }
    )

    result = smoke.run_provider_vault_smoke(
        _config(),
        secret_manager=manager,
        openai_transport=openai_transport,
        ollama_transport=ollama_transport,
    )

    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "passed"
    assert result["redacted"] is True
    assert manager.names == [smoke.DEFAULT_PROVIDER_SECRET_NAME]
    assert openai_transport.calls[0]["headers"] == {"Authorization": f"Bearer {credential}"}
    assert ollama_transport.calls[0]["headers"] == {}
    assert credential not in serialized
    assert openai_text not in serialized
    assert ollama_text not in serialized
    assert serialized.count("[redacted]") == 3


def test_provider_vault_smoke_fails_closed_when_model_is_missing() -> None:
    with pytest.raises(smoke.LiveProviderVaultSmokeError, match=smoke.MODEL_ENV):
        smoke.run_from_env(
            {smoke.ENABLED_ENV: "true"},
            secret_manager=TrackingSecretManager("unused"),
        )


def test_provider_vault_smoke_fails_closed_when_secret_is_missing() -> None:
    with pytest.raises(smoke.LiveProviderVaultSmokeError, match="credential lookup"):
        smoke.run_provider_vault_smoke(
            _config(),
            secret_manager=TrackingSecretManager(None),
            openai_transport=RecordingTransport({}),
            ollama_transport=RecordingTransport({}),
        )


def test_provider_vault_smoke_rejects_nonlocal_plaintext_endpoint() -> None:
    with pytest.raises(smoke.LiveProviderVaultSmokeError, match="loopback"):
        smoke.run_provider_vault_smoke(
            _config(openai_base_url="http://provider.internal/v1"),
            secret_manager=TrackingSecretManager("unused"),
            openai_transport=RecordingTransport({}),
            ollama_transport=RecordingTransport({}),
        )


def test_provider_vault_smoke_config_repr_redacts_vault_token() -> None:
    config = _config(vault_token_value="repr-secret-value")

    assert "repr-secret-value" not in repr(config)


def test_provider_vault_smoke_rejects_endpoint_credentials() -> None:
    with pytest.raises(smoke.LiveProviderVaultSmokeError, match="must not contain credentials"):
        smoke.run_provider_vault_smoke(
            _config(ollama_base_url="http://user:password@127.0.0.1:11434"),
            secret_manager=TrackingSecretManager("unused"),
            openai_transport=RecordingTransport({}),
            ollama_transport=RecordingTransport({}),
        )


def test_provider_vault_smoke_rejects_empty_provider_response() -> None:
    with pytest.raises(smoke.LiveProviderVaultSmokeError, match="empty response"):
        smoke.run_provider_vault_smoke(
            _config(),
            secret_manager=TrackingSecretManager("provider-secret"),
            openai_transport=RecordingTransport(
                {"model": "local-smoke-model", "choices": [{"message": {"content": ""}}]}
            ),
            ollama_transport=RecordingTransport(
                {"model": "local-smoke-model", "message": {"content": "ok"}}
            ),
        )


def test_provider_vault_smoke_main_prints_redacted_skip_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert smoke.main(env={}) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
    assert payload["redacted"] is True


def test_provider_vault_smoke_main_redacts_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_env: object) -> dict[str, object]:
        raise RuntimeError("unexpected-secret-value")

    monkeypatch.setattr(smoke, "run_from_env", fail)

    assert smoke.main(env={smoke.ENABLED_ENV: "true"}) == 1
    output = capsys.readouterr().out
    assert "unexpected-secret-value" not in output
    assert json.loads(output)["redacted"] is True
