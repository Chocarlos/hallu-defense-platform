from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from hallu_defense.config import (
    RagRuntimeConfigurationError,
    RuntimeTransportConfigurationError,
    Settings,
    is_kind_internal_opensearch_http,
    validate_rag_index_settings,
    validate_runtime_transport_settings,
)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "hybrid-rag-test",
        "auth_required": False,
        "allowed_workspace": Path.cwd(),
        "max_command_seconds": 5,
        "max_output_chars": 1000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_hybrid_requires_both_postgres_and_opensearch() -> None:
    with pytest.raises(RagRuntimeConfigurationError, match="POSTGRES_DSN"):
        validate_rag_index_settings(
            _settings(
                rag_index_backend="hybrid",
                postgres_dsn=None,
                opensearch_endpoint="https://search.example.test",
            )
        )

    with pytest.raises(RagRuntimeConfigurationError, match="endpoint"):
        validate_rag_index_settings(
            _settings(
                rag_index_backend="hybrid",
                postgres_dsn="postgresql://runtime@postgres/hallu",
                opensearch_endpoint="",
            )
        )


def test_production_requires_hybrid_vault_authorization() -> None:
    with pytest.raises(RagRuntimeConfigurationError, match="hybrid"):
        validate_rag_index_settings(
            _settings(environment="production", rag_index_backend="pgvector")
        )

    with pytest.raises(RagRuntimeConfigurationError, match="authorization"):
        validate_rag_index_settings(
            _settings(
                environment="production",
                rag_index_backend="hybrid",
                postgres_dsn="postgresql://runtime@postgres/hallu",
                opensearch_endpoint="https://search.example.test",
                secrets_backend="vault",
            )
        )

    settings = _settings(
        environment="production",
        rag_index_backend="hybrid",
        postgres_dsn="postgresql://runtime@postgres/hallu",
        opensearch_endpoint="https://search.example.test",
        opensearch_authorization_secret_name="rag/opensearch/authorization",
        secrets_backend="vault",
    )

    validate_rag_index_settings(settings)


@pytest.mark.parametrize(
    "secret_name",
    [
        "Basic embedded-credential",
        "Bearer embedded-token",
        "/rag/opensearch/authorization",
        "rag/../authorization",
        "rag//authorization",
    ],
)
def test_opensearch_authorization_requires_logical_secret_name(
    secret_name: str,
) -> None:
    with pytest.raises(RagRuntimeConfigurationError, match="logical SecretManager"):
        validate_rag_index_settings(
            _settings(
                environment="production",
                rag_index_backend="hybrid",
                postgres_dsn="postgresql://runtime@postgres/hallu",
                opensearch_endpoint="https://search.example.test",
                opensearch_authorization_secret_name=secret_name,
                secrets_backend="vault",
            )
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://evil-hallu-defense-opensearch:9200",
        "http://hallu-defense-opensearch.example.test:9200",
        "http://user@hallu-defense-opensearch:9200",
        "http://hallu-defense-opensearch:9200/health",
        "http://hallu-defense-opensearch:9201",
        "https://hallu-defense-opensearch:9200",
    ],
)
def test_kind_insecure_http_gate_rejects_every_non_exact_endpoint(endpoint: str) -> None:
    settings = _settings(
        environment="production",
        rag_index_backend="hybrid",
        postgres_dsn="postgresql://runtime@postgres/hallu",
        opensearch_endpoint=endpoint,
        opensearch_kind_insecure_http_enabled=True,
    )

    assert is_kind_internal_opensearch_http(settings) is False
    with pytest.raises(RagRuntimeConfigurationError, match="exact internal kind"):
        validate_rag_index_settings(settings)


def test_kind_insecure_http_gate_accepts_only_explicit_exact_service_without_secret() -> None:
    settings = _settings(
        environment="production",
        rag_index_backend="hybrid",
        postgres_dsn="postgresql://runtime@postgres/hallu",
        opensearch_endpoint="http://hallu-defense-opensearch:9200",
        opensearch_kind_insecure_http_enabled=True,
        outbound_https_allowed_origins=("https://vault.example.test",),
    )

    assert is_kind_internal_opensearch_http(settings) is True
    validate_rag_index_settings(settings)
    validate_runtime_transport_settings(settings)

    with pytest.raises(RagRuntimeConfigurationError, match="must not receive credentials"):
        validate_rag_index_settings(
            replace(
                settings,
                opensearch_authorization_secret_name=(
                    "rag/opensearch/authorization"
                ),
            )
        )


def test_opensearch_origin_must_be_in_production_outbound_allowlist() -> None:
    settings = _settings(
        environment="production",
        rag_index_backend="hybrid",
        opensearch_endpoint="https://search.example.test",
        outbound_https_allowed_origins=("https://vault.example.test",),
    )

    with pytest.raises(
        RuntimeTransportConfigurationError,
        match="HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
    ):
        validate_runtime_transport_settings(settings)

    validate_runtime_transport_settings(
        replace(
            settings,
            outbound_https_allowed_origins=("https://search.example.test",),
        )
    )


def test_opensearch_ca_path_is_optional_but_must_exist_when_configured(
    tmp_path: Path,
) -> None:
    validate_rag_index_settings(
        _settings(
            rag_index_backend="hybrid",
            postgres_dsn="postgresql://runtime@postgres/hallu",
            opensearch_ca_cert_path=None,
        )
    )

    with pytest.raises(RagRuntimeConfigurationError, match="CA_CERT_PATH"):
        validate_rag_index_settings(
            _settings(
                rag_index_backend="hybrid",
                postgres_dsn="postgresql://runtime@postgres/hallu",
                opensearch_ca_cert_path=tmp_path / "missing.pem",
            )
        )
