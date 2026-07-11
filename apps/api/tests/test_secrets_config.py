from __future__ import annotations

import copy

import pytest

from scripts.ci.check_secrets_config import (
    BOOTSTRAP_LOCAL_VAULT_PATH,
    DOCKER_COMPOSE_PATH,
    DOC_PATH,
    ENV_EXAMPLE_PATH,
    LIVE_PROVIDER_VAULT_SMOKE_PATH,
    LIVE_VAULT_SECRETS_SMOKE_PATH,
    LIVE_WORKFLOW_PATH,
    MAKEFILE_PATH,
    POLICY_PATH,
    PROVIDERS_PATH,
    SECURITY_PATH,
    SECRETS_SERVICE_PATH,
    SecretsConfigError,
    load_policy,
    validate_policy,
    validate_supporting_files,
)


def test_secrets_policy_validates_vault_compatible_defaults() -> None:
    policy = load_policy(POLICY_PATH)

    validate_policy(policy)

    production = policy["production"]
    assert isinstance(production, dict)
    assert production["backend"] == "vault"
    assert production["log_secret_values"] is False
    local = policy["local_development"]
    assert isinstance(local, dict)
    assert local["backend"] == "env"
    assert "production" in local["forbidden_environments"]


def test_secrets_policy_rejects_env_backend_for_production() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    assert isinstance(policy, dict)
    production = policy["production"]
    assert isinstance(production, dict)
    production["backend"] = "env"

    with pytest.raises(SecretsConfigError, match="production.backend"):
        validate_policy(policy)


def test_secrets_policy_rejects_raw_token_fields() -> None:
    policy = copy.deepcopy(load_policy(POLICY_PATH))
    assert isinstance(policy, dict)
    production = policy["production"]
    assert isinstance(production, dict)
    production["token"] = "do-not-put-values-here"

    with pytest.raises(SecretsConfigError, match="raw token"):
        validate_policy(policy)


def test_supporting_files_must_document_required_config() -> None:
    with pytest.raises(SecretsConfigError, match=".env.example missing keys"):
        validate_supporting_files(
            env_example_text="HALLU_DEFENSE_SECRETS_BACKEND=env\n",
            docs_text="Vault-compatible HALLU_DEFENSE_VAULT_TOKEN_ENV",
            security_text="Vault-compatible secret manager",
        )


def test_supporting_files_validate_local_vault_wiring() -> None:
    validate_supporting_files(
        env_example_text=ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
        docs_text=DOC_PATH.read_text(encoding="utf-8"),
        security_text=SECURITY_PATH.read_text(encoding="utf-8"),
        compose_text=DOCKER_COMPOSE_PATH.read_text(encoding="utf-8"),
        bootstrap_text=BOOTSTRAP_LOCAL_VAULT_PATH.read_text(encoding="utf-8"),
        live_smoke_text=LIVE_VAULT_SECRETS_SMOKE_PATH.read_text(encoding="utf-8"),
        provider_smoke_text=LIVE_PROVIDER_VAULT_SMOKE_PATH.read_text(encoding="utf-8"),
        providers_text=PROVIDERS_PATH.read_text(encoding="utf-8"),
        secrets_service_text=SECRETS_SERVICE_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )


def test_supporting_files_reject_missing_local_vault_service() -> None:
    with pytest.raises(SecretsConfigError, match="service vault"):
        validate_supporting_files(
            env_example_text=ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
            docs_text=DOC_PATH.read_text(encoding="utf-8"),
            security_text=SECURITY_PATH.read_text(encoding="utf-8"),
            compose_text="services: {}\n",
            bootstrap_text=BOOTSTRAP_LOCAL_VAULT_PATH.read_text(encoding="utf-8"),
            live_smoke_text=LIVE_VAULT_SECRETS_SMOKE_PATH.read_text(encoding="utf-8"),
            provider_smoke_text=LIVE_PROVIDER_VAULT_SMOKE_PATH.read_text(encoding="utf-8"),
            providers_text=PROVIDERS_PATH.read_text(encoding="utf-8"),
            secrets_service_text=SECRETS_SERVICE_PATH.read_text(encoding="utf-8"),
            makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
            live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        )


def test_supporting_files_reject_missing_provider_vault_smoke() -> None:
    with pytest.raises(SecretsConfigError, match="live_provider_vault_smoke.py"):
        validate_supporting_files(
            env_example_text=ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
            docs_text=DOC_PATH.read_text(encoding="utf-8"),
            security_text=SECURITY_PATH.read_text(encoding="utf-8"),
            compose_text=DOCKER_COMPOSE_PATH.read_text(encoding="utf-8"),
            bootstrap_text=BOOTSTRAP_LOCAL_VAULT_PATH.read_text(encoding="utf-8"),
            live_smoke_text=LIVE_VAULT_SECRETS_SMOKE_PATH.read_text(encoding="utf-8"),
            provider_smoke_text="",
            providers_text=PROVIDERS_PATH.read_text(encoding="utf-8"),
            secrets_service_text=SECRETS_SERVICE_PATH.read_text(encoding="utf-8"),
            makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
            live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        )


def test_supporting_files_reject_unbounded_provider_response_reader() -> None:
    providers_text = PROVIDERS_PATH.read_text(encoding="utf-8").replace(
        "response.read(MAX_PROVIDER_HTTP_RESPONSE_BYTES + 1)",
        "response.read()",
    )

    with pytest.raises(SecretsConfigError, match="bounded HTTP response marker"):
        validate_supporting_files(
            env_example_text=ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
            docs_text=DOC_PATH.read_text(encoding="utf-8"),
            security_text=SECURITY_PATH.read_text(encoding="utf-8"),
            compose_text=DOCKER_COMPOSE_PATH.read_text(encoding="utf-8"),
            bootstrap_text=BOOTSTRAP_LOCAL_VAULT_PATH.read_text(encoding="utf-8"),
            live_smoke_text=LIVE_VAULT_SECRETS_SMOKE_PATH.read_text(encoding="utf-8"),
            provider_smoke_text=LIVE_PROVIDER_VAULT_SMOKE_PATH.read_text(encoding="utf-8"),
            providers_text=providers_text,
            secrets_service_text=SECRETS_SERVICE_PATH.read_text(encoding="utf-8"),
            makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
            live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
        )
