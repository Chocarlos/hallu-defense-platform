from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import pytest

import hallu_defense.services.secrets as secrets_module
import hallu_defense.runtime_secrets as runtime_secrets
from hallu_defense.config import Settings, load_settings
from hallu_defense.services.secrets import (
    MAX_VAULT_HTTP_RESPONSE_BYTES,
    EnvSecretManager,
    SecretAccessError,
    SecretConfigurationError,
    SecretNotFoundError,
    SecretResponseTooLargeError,
    VaultSecretManager,
    _urllib_get_json,
    create_secret_manager,
)


class FakeHttpResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_amount: int | None = None

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        self.read_amount = amount
        return self.payload if amount < 0 else self.payload[:amount]


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "2026-07-07",
        "auth_required": False,
        "allowed_workspace": ".",
        "max_command_seconds": 30,
        "max_output_chars": 12000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_env_secret_manager_reads_prefixed_secret_without_repr_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_SECRET_PROVIDERS_OPENAI_API_KEY", "dev-only")
    manager = EnvSecretManager("HALLU_DEFENSE_SECRET_")

    credential = manager.get_secret("providers/openai/api-key")

    assert credential.reveal() == "dev-only"
    assert str(credential) == "[redacted]"
    assert "dev-only" not in repr(credential)
    assert "[redacted]" in repr(credential)


def test_secret_names_reject_traversal() -> None:
    manager = EnvSecretManager("HALLU_DEFENSE_SECRET_")

    with pytest.raises(SecretAccessError, match="traversal"):
        manager.get_secret("providers/../api-key")


def test_env_backend_is_rejected_outside_local_environments() -> None:
    settings = _settings(environment="production", secrets_backend="env")

    with pytest.raises(SecretConfigurationError, match="only allowed"):
        create_secret_manager(settings)


def test_vault_secret_manager_reads_kv2_payload_without_leaking_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_get_json(url: str, headers: Mapping[str, str], timeout: float) -> Mapping[str, object]:
        seen["url"] = url
        seen["headers"] = dict(headers)
        seen["timeout"] = timeout
        return {"data": {"data": {"value": "vault-dev"}}}

    monkeypatch.setenv("HALLU_DEFENSE_VAULT_TOKEN", "vault-dev-token")
    manager = VaultSecretManager(
        address="https://vault.internal",
        mount="secret",
        token_env="HALLU_DEFENSE_VAULT_TOKEN",
        namespace="team-a",
        timeout_seconds=5,
        http_get_json=fake_get_json,
    )

    credential = manager.get_secret("providers/openai/api-key")

    assert credential.reveal() == "vault-dev"
    assert seen["url"] == "https://vault.internal/v1/secret/data/providers/openai/api-key"
    assert seen["headers"] == {
        "X-Vault-Token": "vault-dev-token",
        "X-Vault-Namespace": "team-a",
    }
    assert seen["timeout"] == 5
    assert "vault-dev" not in repr(credential)


def test_vault_backend_requires_token_when_configured_for_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_VAULT_TOKEN", raising=False)
    settings = _settings(
        environment="production",
        secrets_backend="vault",
        vault_addr="https://vault.internal",
        outbound_https_allowed_origins=("https://vault.internal",),
    )

    with pytest.raises(SecretConfigurationError, match="environment variable"):
        create_secret_manager(settings)


def test_vault_backend_reads_rotatable_file_token_for_production(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("HALLU_DEFENSE_VAULT_TOKEN", raising=False)
    token_file = tmp_path / "vault-token"
    token_file.write_text("first-token\n", encoding="utf-8")
    os.chmod(token_file, 0o440)
    seen_tokens: list[str] = []

    def fake_get_json(
        _url: str,
        headers: Mapping[str, str],
        _timeout: float,
    ) -> Mapping[str, object]:
        seen_tokens.append(headers["X-Vault-Token"])
        return {"data": {"data": {"value": "vault-value"}}}

    manager = VaultSecretManager(
        address="https://vault.internal",
        mount="secret",
        token_env="HALLU_DEFENSE_VAULT_TOKEN",
        token_file=token_file,
        require_token=True,
        http_get_json=fake_get_json,
    )
    manager.get_secret("providers/openai/api-key")
    os.chmod(token_file, 0o600)
    token_file.write_text("rotated-token\n", encoding="utf-8")
    os.chmod(token_file, 0o440)
    manager.get_secret("providers/openai/api-key")

    assert seen_tokens == ["first-token", "rotated-token"]


def test_load_settings_preserves_projected_secret_path_across_rotation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    mount = tmp_path / "projected"
    first_version = mount / "..2026_07_10_12_00_00.000000001"
    second_version = mount / "..2026_07_10_12_01_00.000000002"
    first_version.mkdir(parents=True)
    second_version.mkdir()
    (first_version / "vault-token").write_text("first-token\n", encoding="utf-8")
    (second_version / "vault-token").write_text("second-token\n", encoding="utf-8")
    os.chmod(first_version / "vault-token", 0o440)
    os.chmod(second_version / "vault-token", 0o440)
    token_path = mount / "vault-token"
    try:
        (mount / "..data").symlink_to(first_version.name, target_is_directory=True)
        token_path.symlink_to("..data/vault-token")
    except OSError:
        pytest.skip("symlink creation is unavailable for this test identity")

    monkeypatch.setattr(runtime_secrets, "_is_root_owned", lambda _metadata: True)
    monkeypatch.setattr(
        runtime_secrets,
        "_path_is_on_read_only_mount",
        lambda _path: True,
    )
    monkeypatch.setenv("HALLU_DEFENSE_ENV", "local")
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_TOKEN_FILE", str(token_path))
    settings = load_settings()
    assert settings.vault_token_file == token_path
    assert settings.vault_token_file.is_symlink()

    seen_tokens: list[str] = []

    def fake_get_json(
        _url: str,
        headers: Mapping[str, str],
        _timeout: float,
    ) -> Mapping[str, object]:
        seen_tokens.append(headers["X-Vault-Token"])
        return {"data": {"data": {"value": "vault-value"}}}

    manager = VaultSecretManager(
        address="https://vault.internal",
        mount="secret",
        token_env="HALLU_DEFENSE_VAULT_TOKEN",
        token_file=settings.vault_token_file,
        require_token=True,
        http_get_json=fake_get_json,
    )
    manager.get_secret("providers/openai/api-key")

    replacement = mount / "..data-next"
    replacement.symlink_to(second_version.name, target_is_directory=True)
    try:
        os.replace(replacement, mount / "..data")
    except OSError:
        pytest.skip("atomic projected-Secret symlink replacement is unavailable")
    manager.get_secret("providers/openai/api-key")

    assert seen_tokens == ["first-token", "second-token"]


def test_settings_repr_redacts_postgres_dsn() -> None:
    settings = _settings(postgres_dsn="postgresql://user:super-secret@db/app")

    assert "super-secret" not in repr(settings)
    assert "postgres_dsn" not in repr(settings)


def test_vault_secret_manager_maps_missing_field_to_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_TOKEN", "vault-dev-token")
    manager = VaultSecretManager(
        address="https://vault.internal",
        mount="secret",
        token_env="HALLU_DEFENSE_VAULT_TOKEN",
        http_get_json=lambda _url, _headers, _timeout: {"data": {"data": {"other": "value"}}},
    )

    with pytest.raises(SecretNotFoundError, match="field"):
        manager.get_secret("providers/openai/api-key")


def test_vault_http_reader_rejects_response_over_one_mib(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeHttpResponse(b"x" * (MAX_VAULT_HTTP_RESPONSE_BYTES + 1))
    monkeypatch.setattr(
        secrets_module,
        "open_url_no_redirect",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(SecretResponseTooLargeError, match="1 MiB"):
        _urllib_get_json("https://vault.internal/v1/secret/data/test", {}, 3)

    assert response.read_amount == MAX_VAULT_HTTP_RESPONSE_BYTES + 1


def test_vault_http_reader_maps_invalid_json_to_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeHttpResponse(b"not-json")
    monkeypatch.setattr(
        secrets_module,
        "open_url_no_redirect",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(SecretAccessError, match="UTF-8 JSON"):
        _urllib_get_json("https://vault.internal/v1/secret/data/test", {}, 3)


def test_vault_http_reader_scopes_custom_ca_to_vault_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca_path = tmp_path / "vault-ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    ssl_context = object()
    seen: dict[str, object] = {}
    response = FakeHttpResponse(b'{"data":{}}')

    def fake_create_default_context(*, cafile: str) -> object:
        seen["cafile"] = cafile
        return ssl_context

    def fake_urlopen(*_args: object, **kwargs: object) -> FakeHttpResponse:
        seen["context"] = kwargs.get("context")
        return response

    monkeypatch.setattr(secrets_module.ssl, "create_default_context", fake_create_default_context)
    monkeypatch.setattr(secrets_module, "open_url_no_redirect", fake_urlopen)

    assert _urllib_get_json(
        "https://vault.internal/v1/secret/data/test",
        {},
        3,
        ca_cert_path=ca_path,
    ) == {"data": {}}
    assert seen == {"cafile": str(ca_path), "context": ssl_context}


def test_vault_secret_manager_rejects_missing_custom_ca(tmp_path: Path) -> None:
    with pytest.raises(SecretConfigurationError, match="CA certificate"):
        VaultSecretManager(
            address="https://vault.internal",
            mount="secret",
            token_env="HALLU_DEFENSE_VAULT_TOKEN",
            ca_cert_path=tmp_path / "missing-ca.pem",
        )
