from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "infra" / "security" / "secrets-policy.json"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
DOC_PATH = ROOT / "docs" / "security" / "secrets.md"
SECURITY_PATH = ROOT / "SECURITY.md"

REQUIRED_ENV_EXAMPLE_KEYS = {
    "HALLU_DEFENSE_SECRETS_BACKEND",
    "HALLU_DEFENSE_ENV_SECRET_PREFIX",
    "HALLU_DEFENSE_VAULT_ADDR",
    "HALLU_DEFENSE_VAULT_MOUNT",
    "HALLU_DEFENSE_VAULT_NAMESPACE",
    "HALLU_DEFENSE_VAULT_TOKEN_ENV",
    "HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS",
}


class SecretsConfigError(ValueError):
    pass


def load_policy(path: Path = POLICY_PATH) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SecretsConfigError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return payload


def validate_policy(policy: Mapping[str, object]) -> None:
    errors: list[str] = []
    if policy.get("schema_version") != "secrets-policy.v1":
        errors.append("schema_version must be secrets-policy.v1")

    production = _mapping(policy.get("production"), "production", errors)
    if production.get("backend") != "vault":
        errors.append("production.backend must be vault")
    if production.get("required") is not True:
        errors.append("production.required must be true")
    if production.get("log_secret_values") is not False:
        errors.append("production.log_secret_values must be false")
    if production.get("audit_secret_values") is not False:
        errors.append("production.audit_secret_values must be false")
    if production.get("default_token_env_var") != "HALLU_DEFENSE_VAULT_TOKEN":
        errors.append("production.default_token_env_var must reference HALLU_DEFENSE_VAULT_TOKEN")
    if _contains_raw_secret_field(production):
        errors.append("production policy must reference token env vars, not raw token values")

    local = _mapping(policy.get("local_development"), "local_development", errors)
    if local.get("backend") != "env":
        errors.append("local_development.backend must be env")
    if local.get("allowed") is not True:
        errors.append("local_development.allowed must be true")
    if local.get("env_prefix") != "HALLU_DEFENSE_SECRET_":
        errors.append("local_development.env_prefix must be HALLU_DEFENSE_SECRET_")
    forbidden_environments = local.get("forbidden_environments")
    if not isinstance(forbidden_environments, list) or not {
        "production",
        "staging",
    }.issubset(forbidden_environments):
        errors.append("local_development.forbidden_environments must include production and staging")

    controls = _mapping(policy.get("runtime_controls"), "runtime_controls", errors)
    for key in (
        "secret_values_are_redacted_by_type",
        "secret_names_must_be_relative",
        "path_traversal_forbidden",
        "startup_requires_vault_token_outside_local",
    ):
        if controls.get(key) is not True:
            errors.append(f"runtime_controls.{key} must be true")

    if errors:
        raise SecretsConfigError("\n".join(errors))


def validate_supporting_files(
    env_example_text: str,
    docs_text: str,
    security_text: str,
) -> None:
    errors: list[str] = []
    missing_env_keys = sorted(
        key for key in REQUIRED_ENV_EXAMPLE_KEYS if f"{key}=" not in env_example_text
    )
    if missing_env_keys:
        errors.append(f".env.example missing keys: {', '.join(missing_env_keys)}")

    if "HALLU_DEFENSE_VAULT_TOKEN=" in env_example_text:
        errors.append(".env.example must not define the raw Vault token variable")
    if "Vault-compatible" not in docs_text or "HALLU_DEFENSE_VAULT_TOKEN_ENV" not in docs_text:
        errors.append("docs/security/secrets.md must document the Vault-compatible configuration")
    if "Vault-compatible secret manager" not in security_text:
        errors.append("SECURITY.md must mention the Vault-compatible secret manager")

    if errors:
        raise SecretsConfigError("\n".join(errors))


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _contains_raw_secret_field(mapping: Mapping[str, object]) -> bool:
    return any(key in {"token", "secret", "password", "client_secret"} for key in mapping)


def main() -> None:
    policy = load_policy()
    validate_policy(policy)
    validate_supporting_files(
        env_example_text=ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
        docs_text=DOC_PATH.read_text(encoding="utf-8"),
        security_text=SECURITY_PATH.read_text(encoding="utf-8"),
    )
    print("Validated Vault-compatible secrets configuration.")


if __name__ == "__main__":
    main()
