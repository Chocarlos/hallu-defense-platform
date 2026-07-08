from __future__ import annotations

from collections.abc import Mapping

import pytest

from hallu_defense.config import Settings
from hallu_defense.services.secrets import (
    EnvSecretManager,
    SecretAccessError,
    SecretConfigurationError,
    SecretNotFoundError,
    VaultSecretManager,
    create_secret_manager,
)


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
    )

    with pytest.raises(SecretConfigurationError, match="environment variable"):
        create_secret_manager(settings)


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
