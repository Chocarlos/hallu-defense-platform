from __future__ import annotations

import os
from pathlib import Path

import pytest

from hallu_defense.config import (
    OpenSearchBootstrapConfigurationError,
    RUNTIME_ROLE_API,
    RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
    RUNTIME_ROLE_WORKER,
    RagRuntimeConfigurationError,
    RuntimeRoleConfigurationError,
    RuntimeTransportConfigurationError,
    load_settings,
)


def test_bootstrap_role_has_safe_local_cli_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_runtime_env(monkeypatch)

    settings = load_settings(
        expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    )

    assert settings.runtime_role == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    assert settings.rag_index_backend == "opensearch"
    assert settings.opensearch_endpoint == "http://localhost:9200"
    assert settings.opensearch_index_name == "hallu_evidence"


def test_bootstrap_role_cannot_be_selected_without_pinned_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_runtime_env(monkeypatch)
    monkeypatch.setenv(
        "HALLU_DEFENSE_RUNTIME_ROLE",
        RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
    )

    with pytest.raises(RuntimeRoleConfigurationError, match="pinned CLI"):
        load_settings()


@pytest.mark.parametrize(
    "expected_role",
    [RUNTIME_ROLE_API, RUNTIME_ROLE_WORKER],
)
def test_api_and_worker_reject_bootstrap_role(
    monkeypatch: pytest.MonkeyPatch,
    expected_role: str,
) -> None:
    _clear_runtime_env(monkeypatch)
    monkeypatch.setenv(
        "HALLU_DEFENSE_RUNTIME_ROLE",
        RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
    )

    with pytest.raises(RuntimeRoleConfigurationError, match="executable runtime role"):
        load_settings(expected_runtime_role=expected_role)


def test_production_bootstrap_loads_only_vault_and_opensearch_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_external_production(tmp_path, monkeypatch)

    settings = load_settings(
        expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    )

    assert settings.runtime_role == RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    assert settings.rag_index_backend == "opensearch"
    assert settings.postgres_dsn is None
    assert settings.auth_required is False
    assert settings.provider_backend == "mock"
    assert settings.sandbox_backend == "docker"
    assert settings.otel_exporter == "memory"


@pytest.mark.parametrize(
    ("setting", "message"),
    [
        ("HALLU_DEFENSE_VAULT_CA_CERT_PATH", "VAULT_CA_CERT_PATH"),
        ("HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH", "OPENSEARCH_CA_CERT_PATH"),
    ],
)
def test_production_bootstrap_requires_managed_ca_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    message: str,
) -> None:
    _configure_external_production(tmp_path, monkeypatch)
    monkeypatch.delenv(setting)

    with pytest.raises(OpenSearchBootstrapConfigurationError, match=message):
        load_settings(expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP)


def test_production_bootstrap_requires_configured_vault_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_external_production(tmp_path, monkeypatch)
    monkeypatch.delenv("HALLU_DEFENSE_VAULT_TOKEN_FILE")

    with pytest.raises(RuntimeRoleConfigurationError, match="VAULT_TOKEN_FILE"):
        load_settings(expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP)


@pytest.mark.parametrize(
    ("setting", "value", "error_type", "message"),
    [
        (
            "HALLU_DEFENSE_RAG_INDEX_BACKEND",
            "hybrid",
            RagRuntimeConfigurationError,
            "opensearch RAG backend",
        ),
        (
            "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME",
            "unsafe-index-name",
            OpenSearchBootstrapConfigurationError,
            "safe identifier",
        ),
        (
            "HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS",
            "0",
            OpenSearchBootstrapConfigurationError,
            "VAULT_TIMEOUT_SECONDS",
        ),
        (
            "HALLU_DEFENSE_VAULT_TOKEN_ENV",
            "invalid-token-name",
            RuntimeRoleConfigurationError,
            "must not configure HALLU_DEFENSE_VAULT_TOKEN_ENV",
        ),
        (
            "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
            "Basic embedded-value",
            RagRuntimeConfigurationError,
            "logical SecretManager",
        ),
    ],
)
def test_production_bootstrap_rejects_invalid_minimal_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    value: str,
    error_type: type[ValueError],
    message: str,
) -> None:
    _configure_external_production(tmp_path, monkeypatch)
    monkeypatch.setenv(setting, value)

    with pytest.raises(error_type, match=message):
        load_settings(expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        (
            "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
            "http://search.example.test:9200",
        ),
        (
            "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
            "https://vault.example.test",
        ),
    ],
)
def test_external_production_bootstrap_requires_https_allowlisted_opensearch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    value: str,
) -> None:
    _configure_external_production(tmp_path, monkeypatch)
    monkeypatch.setenv(setting, value)

    with pytest.raises(
        RuntimeTransportConfigurationError,
        match="HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
    ):
        load_settings(expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP)


def test_kind_bootstrap_allows_only_exact_internal_http_without_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_external_production(tmp_path, monkeypatch)
    monkeypatch.setenv(
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "http://hallu-defense-opensearch:9200",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_OPENSEARCH_KIND_INSECURE_HTTP_ENABLED",
        "true",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "https://vault.example.test",
    )
    monkeypatch.delenv("HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME")
    monkeypatch.delenv("HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH")

    settings = load_settings(
        expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP
    )

    assert settings.opensearch_kind_insecure_http_enabled is True
    assert settings.opensearch_authorization_secret_name is None
    assert settings.opensearch_ca_cert_path is None

    monkeypatch.setenv(
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "http://other-opensearch:9200",
    )
    with pytest.raises(RagRuntimeConfigurationError, match="exact internal kind"):
        load_settings(expected_runtime_role=RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP)


def _configure_external_production(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_runtime_env(monkeypatch)
    vault_ca = tmp_path / "vault-ca.crt"
    opensearch_ca = tmp_path / "opensearch-ca.crt"
    vault_token = tmp_path / "vault-token"
    vault_ca.write_text("fixture-ca", encoding="utf-8")
    opensearch_ca.write_text("fixture-ca", encoding="utf-8")
    vault_token.write_text("guard-value\n", encoding="utf-8")
    vault_token.chmod(0o400)
    values = {
        "HALLU_DEFENSE_ENV": "production",
        "HALLU_DEFENSE_RUNTIME_ROLE": RUNTIME_ROLE_OPENSEARCH_BOOTSTRAP,
        "HALLU_DEFENSE_RAG_INDEX_BACKEND": "opensearch",
        "HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS": "5",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://search.example.test",
        "HALLU_DEFENSE_OPENSEARCH_INDEX_NAME": "hallu_evidence",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": (
            "rag/opensearch/authorization"
        ),
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": str(opensearch_ca),
        "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
        "HALLU_DEFENSE_VAULT_ADDR": "https://vault.example.test",
        "HALLU_DEFENSE_VAULT_MOUNT": "secret",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE": str(vault_token),
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH": str(vault_ca),
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
            "https://vault.example.test,https://search.example.test"
        ),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def _clear_runtime_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("HALLU_DEFENSE_"):
            monkeypatch.delenv(key, raising=False)
