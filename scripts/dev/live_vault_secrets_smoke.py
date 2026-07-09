"""Env-gated smoke for the local Vault-backed SecretManager path."""

from __future__ import annotations

import base64
import json
import os
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import Settings  # noqa: E402
from hallu_defense.services.secrets import (  # noqa: E402
    HttpJsonGetter,
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
    VaultSecretManager,
    create_secret_manager,
)
from scripts.dev.bootstrap_local_vault import (  # noqa: E402
    DEFAULT_LOCAL_VAULT_ADDR,
    DEFAULT_LOCAL_VAULT_MOUNT,
    DEFAULT_LOCAL_VAULT_TOKEN,
    DEFAULT_LOCAL_VAULT_TOKEN_ENV,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_VAULT_SECRETS_SMOKE_ENABLED"
ADDR_ENV = "HALLU_DEFENSE_LIVE_VAULT_ADDR"
MOUNT_ENV = "HALLU_DEFENSE_LIVE_VAULT_MOUNT"
TOKEN_ENV_ENV = "HALLU_DEFENSE_LIVE_VAULT_TOKEN_ENV"
TIMEOUT_ENV = "HALLU_DEFENSE_LIVE_VAULT_TIMEOUT_SECONDS"

BACKUP_ENCRYPTION_SECRET_NAME = "backup/encryption-key"
LOCAL_VAULT_SECRET_NAMES: tuple[str, ...] = (
    "observability/metrics-scrape-token",
    "auth/trusted-header-signing-key",
    BACKUP_ENCRYPTION_SECRET_NAME,
)


class LiveVaultSecretsSmokeError(RuntimeError):
    pass


@dataclass(frozen=True)
class LiveVaultSecretsSmokeConfig:
    address: str
    mount: str
    token_env: str
    token_value: str
    timeout_seconds: int = 3


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    secret_manager: SecretManager | None = None,
    http_get_json: HttpJsonGetter | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    if not _enabled(effective_env.get(ENABLED_ENV, "")):
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live Vault secrets smoke",
            "secret_names_verified": [],
            "backup_key_format_verified": False,
        }

    config = _config_from_env(effective_env)
    manager = secret_manager or _build_secret_manager(config, http_get_json=http_get_json)
    with _patched_token_env(config.token_env, config.token_value):
        return verify_vault_secrets(manager, vault_addr=config.address, mount=config.mount)


def verify_vault_secrets(
    secret_manager: SecretManager,
    *,
    vault_addr: str,
    mount: str,
) -> dict[str, object]:
    verified_names: list[str] = []
    backup_key_format_verified = False
    try:
        for secret_name in LOCAL_VAULT_SECRET_NAMES:
            credential = secret_manager.get_secret(secret_name)
            value = credential.reveal()
            if not value:
                raise LiveVaultSecretsSmokeError(f"secret {secret_name!r} was empty")
            if value in repr(credential) or value in str(credential):
                raise LiveVaultSecretsSmokeError(f"secret {secret_name!r} leaked through repr/str")
            if secret_name == BACKUP_ENCRYPTION_SECRET_NAME:
                backup_key_format_verified = _is_fernet_key(value)
                if not backup_key_format_verified:
                    raise LiveVaultSecretsSmokeError(
                        "backup/encryption-key must be a urlsafe base64 32-byte key"
                    )
            verified_names.append(secret_name)
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError) as exc:
        raise LiveVaultSecretsSmokeError("Vault SecretManager lookup failed") from exc

    return {
        "status": "passed",
        "vault_addr": vault_addr.rstrip("/"),
        "mount": mount.strip("/"),
        "secret_names_verified": verified_names,
        "backup_key_format_verified": backup_key_format_verified,
    }


def _build_secret_manager(
    config: LiveVaultSecretsSmokeConfig,
    *,
    http_get_json: HttpJsonGetter | None,
) -> SecretManager:
    if http_get_json is not None:
        return VaultSecretManager(
            address=config.address,
            mount=config.mount,
            token_env=config.token_env,
            timeout_seconds=config.timeout_seconds,
            http_get_json=http_get_json,
        )
    settings = Settings(
        environment="local",
        policy_version="live-vault-smoke",
        auth_required=False,
        allowed_workspace=ROOT,
        max_command_seconds=5,
        max_output_chars=1000,
        secrets_backend="vault",
        vault_addr=config.address,
        vault_mount=config.mount,
        vault_token_env=config.token_env,
        vault_timeout_seconds=config.timeout_seconds,
    )
    return create_secret_manager(settings)


def _config_from_env(env: Mapping[str, str]) -> LiveVaultSecretsSmokeConfig:
    token_env = _optional(env, TOKEN_ENV_ENV) or DEFAULT_LOCAL_VAULT_TOKEN_ENV
    address = (
        _optional(env, ADDR_ENV)
        or _optional(env, "HALLU_DEFENSE_VAULT_ADDR")
        or DEFAULT_LOCAL_VAULT_ADDR
    )
    mount = (
        _optional(env, MOUNT_ENV)
        or _optional(env, "HALLU_DEFENSE_VAULT_MOUNT")
        or DEFAULT_LOCAL_VAULT_MOUNT
    )
    return LiveVaultSecretsSmokeConfig(
        address=address,
        mount=mount,
        token_env=token_env,
        token_value=_optional(env, token_env) or DEFAULT_LOCAL_VAULT_TOKEN,
        timeout_seconds=_int_env(env, TIMEOUT_ENV, 3),
    )


@contextmanager
def _patched_token_env(name: str, value: str) -> Iterator[None]:
    previous = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _is_fernet_key(value: str) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False
    return len(decoded) == 32


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    value = _optional(env, name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise LiveVaultSecretsSmokeError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise LiveVaultSecretsSmokeError(f"{name} must be positive")
    return parsed


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _json_result(result: Mapping[str, object]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    _ = argv
    try:
        result = run_from_env(env)
    except Exception as exc:
        print(_json_result({"status": "failed", "error": str(exc)}))
        return 1
    print(_json_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
