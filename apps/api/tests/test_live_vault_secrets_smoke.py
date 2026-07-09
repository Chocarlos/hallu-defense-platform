from __future__ import annotations

import base64
import json
from collections.abc import Mapping

import pytest

from hallu_defense.services.secrets import SecretValue
from scripts.dev import live_vault_secrets_smoke as smoke
from scripts.dev.bootstrap_local_vault import LOCAL_VAULT_SECRET_NAMES


class _FakeSecretManager:
    def __init__(self, values: Mapping[str, str]) -> None:
        self.values = values

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert field == "value"
        return SecretValue(name=name, _value=self.values[name])


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(b"a" * 32).decode("ascii")


def _secret_values() -> dict[str, str]:
    return {
        "observability/metrics-scrape-token": "metrics-local-value",
        "auth/trusted-header-signing-key": "gateway-local-value",
        "backup/encryption-key": _fernet_key(),
    }


def test_live_vault_smoke_skips_by_default_without_secret_output() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert result["secret_names_verified"] == []
    assert json.dumps(result).find("metrics-local-value") == -1


def test_verify_vault_secrets_uses_secret_manager_and_redacts_values() -> None:
    result = smoke.verify_vault_secrets(
        _FakeSecretManager(_secret_values()),
        vault_addr="http://127.0.0.1:8200",
        mount="secret",
    )

    assert result["status"] == "passed"
    assert result["secret_names_verified"] == list(LOCAL_VAULT_SECRET_NAMES)
    assert result["backup_key_format_verified"] is True
    emitted = json.dumps(result)
    for value in _secret_values().values():
        assert value not in emitted


def test_verify_vault_secrets_rejects_backup_key_with_wrong_shape() -> None:
    values = _secret_values()
    values["backup/encryption-key"] = "not-a-fernet-key"

    with pytest.raises(smoke.LiveVaultSecretsSmokeError, match="backup/encryption-key"):
        smoke.verify_vault_secrets(
            _FakeSecretManager(values),
            vault_addr="http://127.0.0.1:8200",
            mount="secret",
        )


def test_run_from_env_exercises_vault_secret_manager_with_injected_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen_urls: list[str] = []

    def fake_get_json(
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        assert headers == {"X-Vault-Token": "tok"}
        assert timeout_seconds == 9
        seen_urls.append(url)
        secret_name = url.split("/data/", 1)[1]
        value = _secret_values()[secret_name]
        return {"data": {"data": {"value": value}}}

    monkeypatch.delenv("CUSTOM_LOCAL_VAULT_TOKEN", raising=False)
    result = smoke.run_from_env(
        {
            smoke.ENABLED_ENV: "true",
            smoke.ADDR_ENV: "http://127.0.0.1:8200",
            smoke.MOUNT_ENV: "secret",
            smoke.TOKEN_ENV_ENV: "CUSTOM_LOCAL_VAULT_TOKEN",
            "CUSTOM_LOCAL_VAULT_TOKEN": "tok",
            smoke.TIMEOUT_ENV: "9",
        },
        http_get_json=fake_get_json,
    )

    assert result["status"] == "passed"
    assert seen_urls == [
        "http://127.0.0.1:8200/v1/secret/data/observability/metrics-scrape-token",
        "http://127.0.0.1:8200/v1/secret/data/auth/trusted-header-signing-key",
        "http://127.0.0.1:8200/v1/secret/data/backup/encryption-key",
    ]
    assert "CUSTOM_LOCAL_VAULT_TOKEN" not in __import__("os").environ


def test_main_skip_prints_json_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = smoke.main(env={})

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "skipped"
