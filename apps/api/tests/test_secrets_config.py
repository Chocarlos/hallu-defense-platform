from __future__ import annotations

import copy

import pytest

from scripts.ci.check_secrets_config import (
    POLICY_PATH,
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
