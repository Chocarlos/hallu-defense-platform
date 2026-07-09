from __future__ import annotations

import copy
from pathlib import Path

import pytest

from hallu_defense.config import (
    AuthConfigurationError,
    RateLimitConfigurationError,
    Settings,
    validate_auth_settings,
    validate_rate_limit_settings,
)
from scripts.ci.check_auth_config import (
    AuthConfigError,
    load_current_config,
    load_policy,
    validate_policy,
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
