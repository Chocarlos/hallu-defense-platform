from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "infra" / "security" / "secrets-policy.json"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
DOC_PATH = ROOT / "docs" / "security" / "secrets.md"
SECURITY_PATH = ROOT / "SECURITY.md"
DOCKER_COMPOSE_PATH = ROOT / "docker-compose.yml"
BOOTSTRAP_LOCAL_VAULT_PATH = ROOT / "scripts" / "dev" / "bootstrap_local_vault.py"
LIVE_VAULT_SECRETS_SMOKE_PATH = ROOT / "scripts" / "dev" / "live_vault_secrets_smoke.py"
MAKEFILE_PATH = ROOT / "Makefile"
LIVE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "live.yml"

REQUIRED_ENV_EXAMPLE_KEYS = {
    "HALLU_DEFENSE_SECRETS_BACKEND",
    "HALLU_DEFENSE_ENV_SECRET_PREFIX",
    "HALLU_DEFENSE_VAULT_ADDR",
    "HALLU_DEFENSE_VAULT_MOUNT",
    "HALLU_DEFENSE_VAULT_NAMESPACE",
    "HALLU_DEFENSE_VAULT_TOKEN_ENV",
    "HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS",
    "HALLU_DEFENSE_LOCAL_VAULT_DEV_ROOT_TOKEN",
    "HALLU_DEFENSE_LIVE_VAULT_SECRETS_SMOKE_ENABLED",
    "HALLU_DEFENSE_LIVE_VAULT_ADDR",
    "HALLU_DEFENSE_LIVE_VAULT_MOUNT",
    "HALLU_DEFENSE_LIVE_VAULT_TOKEN_ENV",
}
REQUIRED_LOCAL_VAULT_SECRET_NAMES = {
    "observability/metrics-scrape-token",
    "auth/trusted-header-signing-key",
    "backup/encryption-key",
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
    *,
    compose_text: str = "",
    bootstrap_text: str = "",
    live_smoke_text: str = "",
    makefile_text: str = "",
    live_workflow_text: str = "",
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
    _validate_local_vault_compose(compose_text, errors)
    _validate_local_vault_scripts(
        bootstrap_text=bootstrap_text,
        live_smoke_text=live_smoke_text,
        errors=errors,
    )
    if (
        "vault-bootstrap:" not in makefile_text
        or "scripts/dev/bootstrap_local_vault.py" not in makefile_text
    ):
        errors.append("Makefile must expose vault-bootstrap")
    if (
        "vault-live-smoke:" not in makefile_text
        or "scripts/dev/live_vault_secrets_smoke.py" not in makefile_text
    ):
        errors.append("Makefile must expose vault-live-smoke")
    if "vault-live:" not in live_workflow_text or "live_vault_secrets_smoke.py" not in live_workflow_text:
        errors.append("live workflow must include the Vault live smoke job")

    if errors:
        raise SecretsConfigError("\n".join(errors))


def _mapping(value: object, path: str, errors: list[str]) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    errors.append(f"{path} must be an object")
    return {}


def _contains_raw_secret_field(mapping: Mapping[str, object]) -> bool:
    return any(key in {"token", "secret", "password", "client_secret"} for key in mapping)


def _validate_local_vault_compose(compose_text: str, errors: list[str]) -> None:
    if not compose_text.strip():
        errors.append("docker-compose.yml must define the local vault service")
        return
    loaded = yaml.safe_load(compose_text)
    if not isinstance(loaded, Mapping):
        errors.append("docker-compose.yml must contain a YAML object")
        return
    services = _mapping(loaded.get("services"), "docker-compose.yml services", errors)
    vault = _mapping(services.get("vault"), "service vault", errors)
    if vault.get("image") != "hashicorp/vault:1.17":
        errors.append("service vault image must be hashicorp/vault:1.17")
    ports = vault.get("ports")
    if not isinstance(ports, list) or "8200:8200" not in ports:
        errors.append("service vault must expose 8200:8200")
    command = vault.get("command")
    command_tokens: tuple[str, ...]
    if isinstance(command, str):
        command_tokens = tuple(command.split())
    elif isinstance(command, list):
        command_tokens = tuple(str(item) for item in command)
    else:
        command_tokens = ()
    if "-dev" not in command_tokens:
        errors.append("service vault must run in dev mode for local compose")
    if "-dev-root-token-id=${HALLU_DEFENSE_LOCAL_VAULT_DEV_ROOT_TOKEN:-dev-root}" not in command_tokens:
        errors.append("service vault must use the local root-token env override")


def _validate_local_vault_scripts(
    *,
    bootstrap_text: str,
    live_smoke_text: str,
    errors: list[str],
) -> None:
    if not bootstrap_text.strip():
        errors.append("scripts/dev/bootstrap_local_vault.py must exist")
    if not live_smoke_text.strip():
        errors.append("scripts/dev/live_vault_secrets_smoke.py must exist")
    for secret_name in sorted(REQUIRED_LOCAL_VAULT_SECRET_NAMES):
        if secret_name not in bootstrap_text:
            errors.append(f"bootstrap_local_vault.py must seed {secret_name}")
        if secret_name not in live_smoke_text:
            errors.append(f"live_vault_secrets_smoke.py must verify {secret_name}")
    if "HALLU_DEFENSE_LIVE_VAULT_SECRETS_SMOKE_ENABLED" not in live_smoke_text:
        errors.append("live_vault_secrets_smoke.py must be env-gated")
    if "create_secret_manager" not in live_smoke_text or "VaultSecretManager" not in live_smoke_text:
        errors.append("live_vault_secrets_smoke.py must exercise services/secrets.py")


def main() -> None:
    policy = load_policy()
    validate_policy(policy)
    validate_supporting_files(
        env_example_text=ENV_EXAMPLE_PATH.read_text(encoding="utf-8"),
        docs_text=DOC_PATH.read_text(encoding="utf-8"),
        security_text=SECURITY_PATH.read_text(encoding="utf-8"),
        compose_text=DOCKER_COMPOSE_PATH.read_text(encoding="utf-8"),
        bootstrap_text=BOOTSTRAP_LOCAL_VAULT_PATH.read_text(encoding="utf-8"),
        live_smoke_text=LIVE_VAULT_SECRETS_SMOKE_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        live_workflow_text=LIVE_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print("Validated Vault-compatible secrets configuration.")


if __name__ == "__main__":
    main()
