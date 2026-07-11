from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from urllib.parse import quote

import pytest

from hallu_defense.config import (
    AuthConfigurationError,
    EnvironmentConfigurationError,
    MetricsAuthConfigurationError,
    RateLimitConfigurationError,
    RuntimeTransportConfigurationError,
    Settings,
    load_settings,
    validate_auth_settings,
    validate_metrics_auth_settings,
    validate_rate_limit_settings,
    validate_runtime_transport_settings,
)
from scripts.ci.check_auth_config import (
    AuthConfigError,
    load_current_config,
    load_policy,
    validate_policy,
    validate_live_keycloak_config,
    validate_supporting_files,
)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "test",
        "auth_required": False,
        "allowed_workspace": Path("."),
        "max_command_seconds": 5,
        "max_output_chars": 1000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_auth_settings_reject_production_without_required_auth() -> None:
    settings = _settings(environment="production", auth_required=False)

    with pytest.raises(AuthConfigurationError, match="AUTH_REQUIRED=true"):
        validate_auth_settings(settings)


def test_auth_settings_reject_unsigned_claims_in_production() -> None:
    settings = _settings(
        environment="production",
        auth_required=True,
        auth_claims_mode="unsigned_headers",
    )

    with pytest.raises(AuthConfigurationError, match="signed_headers"):
        validate_auth_settings(settings)


def test_auth_settings_reject_oidc_without_required_configuration() -> None:
    settings = _settings(
        environment="production",
        auth_required=True,
        auth_claims_mode="oidc_jwt",
    )

    with pytest.raises(AuthConfigurationError, match="OIDC_ISSUER"):
        validate_auth_settings(settings)


def test_auth_settings_accept_oidc_claims_in_production() -> None:
    settings = _settings(
        environment="production",
        auth_required=True,
        auth_claims_mode="oidc_jwt",
        oidc_issuer="https://issuer.example",
        oidc_audience="hallu-defense-api",
        oidc_jwks_path=Path("jwks.json"),
    )

    validate_auth_settings(settings)


def test_auth_settings_accept_oidc_remote_jwks_url_in_production() -> None:
    settings = _settings(
        environment="production",
        auth_required=True,
        auth_claims_mode="oidc_jwt",
        oidc_issuer="https://issuer.example",
        oidc_audience="hallu-defense-api",
        oidc_jwks_url="https://issuer.example/jwks.json",
    )

    validate_auth_settings(settings)


def test_auth_settings_reject_insecure_remote_jwks_url_in_production() -> None:
    settings = _settings(
        environment="production",
        auth_required=True,
        auth_claims_mode="oidc_jwt",
        oidc_issuer="https://issuer.example",
        oidc_audience="hallu-defense-api",
        oidc_jwks_url="http://issuer.example/jwks.json",
    )

    with pytest.raises(AuthConfigurationError, match="https"):
        validate_auth_settings(settings)


def test_auth_settings_accept_signed_claims_in_staging() -> None:
    settings = _settings(
        environment="staging",
        auth_required=True,
        auth_claims_mode="signed_headers",
        auth_claims_signature_secret_name="auth/trusted-header-signing-key",
    )

    validate_auth_settings(settings)


def test_metrics_auth_settings_reject_blank_secret_name() -> None:
    settings = _settings(metrics_bearer_token_secret_name="   ")

    with pytest.raises(MetricsAuthConfigurationError, match="must not be blank"):
        validate_metrics_auth_settings(settings)


def test_metrics_auth_settings_reject_production_without_secret_name() -> None:
    settings = _settings(environment="production", secrets_backend="vault")

    with pytest.raises(MetricsAuthConfigurationError, match="METRICS_BEARER_TOKEN_SECRET_NAME"):
        validate_metrics_auth_settings(settings)


def test_metrics_auth_settings_reject_env_backend_in_production() -> None:
    settings = _settings(
        environment="production",
        secrets_backend="env",
        metrics_bearer_token_secret_name="observability/metrics-bearer-token",
    )

    with pytest.raises(MetricsAuthConfigurationError, match="env secrets"):
        validate_metrics_auth_settings(settings)


def test_metrics_auth_settings_accept_unset_secret_name_outside_production() -> None:
    settings = _settings(metrics_bearer_token_secret_name=None)

    validate_metrics_auth_settings(settings)


def test_metrics_auth_settings_accept_vault_backend_in_production() -> None:
    settings = _settings(
        environment="production",
        secrets_backend="vault",
        metrics_bearer_token_secret_name="observability/metrics-bearer-token",
    )

    validate_metrics_auth_settings(settings)


@pytest.mark.parametrize(
    ("overrides", "setting_name"),
    [
        (
            {"secrets_backend": "vault", "vault_addr": "http://vault.internal:8200"},
            "VAULT_ADDR",
        ),
        (
            {
                "provider_backend": "openai-compatible",
                "openai_compatible_base_url": "http://provider.internal/v1",
            },
            "OPENAI_COMPATIBLE_BASE_URL",
        ),
        (
            {"provider_backend": "ollama", "ollama_base_url": "http://ollama.internal:11434"},
            "OLLAMA_BASE_URL",
        ),
    ],
)
def test_runtime_transport_settings_reject_plaintext_production_urls(
    overrides: dict[str, object],
    setting_name: str,
) -> None:
    settings = _settings(
        environment="production",
        outbound_https_allowed_origins=(
            "https://vault.internal:8200",
            "https://provider.internal",
            "https://ollama.internal:11434",
        ),
        **overrides,
    )

    with pytest.raises(RuntimeTransportConfigurationError, match=setting_name):
        validate_runtime_transport_settings(settings)


def test_runtime_transport_settings_allow_local_plaintext_dependencies() -> None:
    settings = _settings(
        environment="local",
        secrets_backend="vault",
        vault_addr="http://127.0.0.1:8200",
        provider_backend="ollama",
        ollama_base_url="http://127.0.0.1:11434",
    )

    validate_runtime_transport_settings(settings)


def test_load_settings_applies_runtime_transport_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    redis_ca_path = tmp_path / "redis-ca.pem"
    vault_token_path = tmp_path / "vault-token"
    redis_ca_path.write_text("test-ca", encoding="utf-8")
    vault_token_path.write_text("test-vault-token\n", encoding="utf-8")
    vault_token_path.chmod(0o400)
    monkeypatch.setenv("HALLU_DEFENSE_ENV", "production")
    monkeypatch.setenv("HALLU_DEFENSE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("HALLU_DEFENSE_AUTH_CLAIMS_MODE", "signed_headers")
    monkeypatch.setenv("HALLU_DEFENSE_CORS_ALLOW_ORIGINS", "https://console.example.test")
    monkeypatch.setenv("HALLU_DEFENSE_SECRETS_BACKEND", "vault")
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_ADDR", "http://vault.internal:8200")
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_TOKEN_FILE", str(vault_token_path))
    monkeypatch.setenv(
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "https://vault.internal:8200,https://search.example.test",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
        "observability/metrics-scrape-token",
    )
    monkeypatch.setenv("HALLU_DEFENSE_SANDBOX_BACKEND", "kubernetes")
    monkeypatch.setenv(
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE",
        "registry.example.test/hallu-sandbox@sha256:" + ("a" * 64),
    )
    monkeypatch.setenv("HALLU_DEFENSE_SANDBOX_KUBERNETES_NAMESPACE", "hallu-sandbox")
    monkeypatch.setenv("HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME", "tenant-workspace")
    monkeypatch.setenv(
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_WORKSPACE_MOUNT_PATH",
        "/workspace",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_SANDBOX_KUBERNETES_NETWORK_POLICY_NAME",
        "sandbox-default-deny",
    )
    monkeypatch.setenv("HALLU_DEFENSE_SANDBOX_KUBERNETES_TENANT_ID", "tenant-a")
    monkeypatch.setenv("HALLU_DEFENSE_PROVIDER_BACKEND", "mock")
    monkeypatch.setenv("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid")
    monkeypatch.setenv("HALLU_DEFENSE_INGESTION_MODE", "async")
    monkeypatch.setenv(
        "HALLU_DEFENSE_POSTGRES_DSN",
        "postgresql://runtime@postgres/hallu"
        "?sslmode=verify-full"
        "&ssl_min_protocol_version=TLSv1.3"
        "&gssencmode=disable"
        f"&sslrootcert={quote(redis_ca_path.resolve().as_posix(), safe='')}",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH",
        str(redis_ca_path.resolve()),
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT",
        "https://search.example.test",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "rag/opensearch/authorization",
    )
    monkeypatch.setenv("HALLU_DEFENSE_OPA_ENABLED", "true")
    monkeypatch.setenv("HALLU_DEFENSE_OPA_PATH", str(Path(sys.executable).resolve()))
    monkeypatch.setenv("HALLU_DEFENSE_OPA_POLICY_DIR", str(tmp_path))
    monkeypatch.setenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setenv(
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH",
        str(redis_ca_path),
    )

    with pytest.raises(RuntimeTransportConfigurationError, match="VAULT_ADDR"):
        load_settings()


def test_rate_limit_settings_reject_non_positive_values() -> None:
    settings = _settings(
        tool_validation_rate_limit_max_requests=0,
        tool_validation_rate_limit_window_seconds=0,
    )

    with pytest.raises(RateLimitConfigurationError, match="RATE_LIMIT_MAX_REQUESTS"):
        validate_rate_limit_settings(settings)


def test_auth_policy_validates_enterprise_defaults() -> None:
    policy = load_policy()

    validate_policy(policy)

    production = policy["production"]
    assert isinstance(production, dict)
    assert production["auth_required"] is True
    assert production["claims_mode"] == "oidc_jwt"
    assert production["allow_unsigned_claim_headers"] is False
    assert production["tenant_source"] == "verified_jwt_claim"
    assert production["jwks_source"] == ["path", "url", "discovery"]


def test_auth_policy_validates_metrics_scrape_auth_baseline() -> None:
    policy = load_policy()

    validate_policy(policy)

    metrics_scrape_auth = policy["metrics_scrape_auth"]
    assert isinstance(metrics_scrape_auth, dict)
    assert metrics_scrape_auth["bearer_token_alternative_allowed"] is True
    assert (
        metrics_scrape_auth["bearer_token_secret_reference_env"]
        == "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME"
    )
    assert metrics_scrape_auth["constant_time_comparison_required"] is True
    assert metrics_scrape_auth["fail_closed_when_unconfigured"] is True


def test_auth_policy_rejects_metrics_scrape_auth_not_fail_closed() -> None:
    policy = copy.deepcopy(load_policy())
    metrics_scrape_auth = policy["metrics_scrape_auth"]
    assert isinstance(metrics_scrape_auth, dict)
    metrics_scrape_auth["fail_closed_when_unconfigured"] = False

    with pytest.raises(AuthConfigError, match="fail_closed_when_unconfigured"):
        validate_policy(policy)


def test_auth_policy_rejects_non_oidc_production_claims() -> None:
    policy = copy.deepcopy(load_policy())
    assert isinstance(policy, dict)
    production = policy["production"]
    assert isinstance(production, dict)
    production["claims_mode"] = "signed_headers"

    with pytest.raises(AuthConfigError, match="production.claims_mode"):
        validate_policy(policy)


def test_auth_config_validates_current_artifacts() -> None:
    (
        env_example_text,
        auth_doc_text,
        security_doc_text,
        config_text,
        auth_service_text,
        api_dependencies_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()

    validate_supporting_files(
        env_example_text=env_example_text,
        auth_doc_text=auth_doc_text,
        security_doc_text=security_doc_text,
        config_text=config_text,
        auth_service_text=auth_service_text,
        api_dependencies_text=api_dependencies_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )


def test_auth_config_requires_ci_wiring() -> None:
    config = list(load_current_config())
    config[7] = config[7].replace("python scripts/ci/check_auth_config.py", "")

    with pytest.raises(AuthConfigError, match="CI workflow"):
        validate_supporting_files(
            env_example_text=config[0],
            auth_doc_text=config[1],
            security_doc_text=config[2],
            config_text=config[3],
            auth_service_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def test_auth_config_requires_oidc_provider_smoke_ci_wiring() -> None:
    config = list(load_current_config())
    config[7] = config[7].replace("python scripts/ci/oidc_provider_smoke.py", "")

    with pytest.raises(AuthConfigError, match="oidc_provider_smoke.py"):
        validate_supporting_files(
            env_example_text=config[0],
            auth_doc_text=config[1],
            security_doc_text=config[2],
            config_text=config[3],
            auth_service_text=config[4],
            api_dependencies_text=config[5],
            makefile_text=config[6],
            ci_workflow_text=config[7],
            security_workflow_text=config[8],
        )


def _live_keycloak_artifacts() -> tuple[str, str, str]:
    root = Path(__file__).parents[3]
    return (
        (root / "scripts/dev/live_keycloak_oidc_smoke.py").read_text(encoding="utf-8"),
        (root / "infra/security/keycloak/realm-hallu-defense.json").read_text(
            encoding="utf-8"
        ),
        (root / ".github/workflows/live.yml").read_text(encoding="utf-8"),
    )


def test_live_keycloak_gate_rejects_in_process_test_client() -> None:
    script, realm, workflow = _live_keycloak_artifacts()

    with pytest.raises(AuthConfigError, match="Uvicorn HTTP boundary"):
        validate_live_keycloak_config(
            live_script_text=f"from fastapi.testclient import TestClient\n{script}",
            realm_text=realm,
            live_workflow_text=workflow,
        )


def test_live_keycloak_gate_requires_limited_client() -> None:
    script, realm_text, workflow = _live_keycloak_artifacts()
    realm = json.loads(realm_text)
    realm["clients"] = [
        client
        for client in realm["clients"]
        if client["clientId"] != "hallu-defense-limited"
    ]

    with pytest.raises(AuthConfigError, match="missing least-privilege client"):
        validate_live_keycloak_config(
            live_script_text=script,
            realm_text=json.dumps(realm),
            live_workflow_text=workflow,
        )


def test_live_keycloak_gate_forbids_global_compose_teardown() -> None:
    script, realm, workflow = _live_keycloak_artifacts()
    unsafe_workflow = workflow.replace(
        "docker compose stop keycloak || true",
        "docker compose down -v || true",
    )

    with pytest.raises(AuthConfigError, match="must not run global docker compose down"):
        validate_live_keycloak_config(
            live_script_text=script,
            realm_text=realm,
            live_workflow_text=unsafe_workflow,
        )
def test_load_settings_normalizes_environment_before_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_ENV", " LOCAL ")

    assert load_settings().environment == "local"


def test_load_settings_rejects_unknown_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_ENV", "prod")

    with pytest.raises(EnvironmentConfigurationError, match="HALLU_DEFENSE_ENV"):
        load_settings()
