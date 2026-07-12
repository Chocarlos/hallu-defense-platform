"""Seed the local Vault dev server with the Batch 7 baseline secrets.

The script is intentionally local-only. It refuses non-loopback Vault addresses
unless explicitly overridden, writes KV v2 payloads, and only reports secret
names/counts, never values.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib import error, parse, request

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_LOCAL_VAULT_ADDR = "http://127.0.0.1:8200"
DEFAULT_LOCAL_VAULT_MOUNT = "secret"
DEFAULT_LOCAL_VAULT_TOKEN_ENV = "HALLU_DEFENSE_LOCAL_VAULT_DEV_ROOT_TOKEN"
DEFAULT_LOCAL_VAULT_TOKEN = "dev-root"

ADDR_ENV = "HALLU_DEFENSE_LOCAL_VAULT_ADDR"
MOUNT_ENV = "HALLU_DEFENSE_LOCAL_VAULT_MOUNT"
TOKEN_ENV_ENV = "HALLU_DEFENSE_LOCAL_VAULT_TOKEN_ENV"
TIMEOUT_ENV = "HALLU_DEFENSE_LOCAL_VAULT_TIMEOUT_SECONDS"
ALLOW_NONLOCAL_ENV = "HALLU_DEFENSE_LOCAL_VAULT_ALLOW_NONLOCAL"

LOCAL_VAULT_SECRET_NAMES: tuple[str, ...] = (
    "observability/metrics-scrape-token",
    "audit/request-commitment-key",
    "approvals/tool-call-commitment-key",
    "auth/trusted-header-signing-key",
    "backup/encryption-key",
    "providers/openai/api-key",
)

RequestJson = Callable[
    [str, str, Mapping[str, str], Mapping[str, object] | None, int],
    Mapping[str, object],
]


class LocalVaultBootstrapError(RuntimeError):
    pass


@dataclass(frozen=True)
class LocalVaultBootstrapConfig:
    address: str
    mount: str
    token_env: str
    token: str
    timeout_seconds: int = 3
    allow_nonlocal: bool = False


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    request_json: RequestJson | None = None,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    config = _config_from_env(effective_env)
    return bootstrap_local_vault(config, request_json=request_json)


def bootstrap_local_vault(
    config: LocalVaultBootstrapConfig,
    *,
    request_json: RequestJson | None = None,
) -> dict[str, object]:
    _validate_config(config)
    requester = request_json or _urllib_request_json
    headers = {"X-Vault-Token": config.token}

    for secret_name in LOCAL_VAULT_SECRET_NAMES:
        requester(
            "PUT",
            _kv2_secret_url(config, secret_name),
            headers,
            {"data": {"value": _secret_value(secret_name)}},
            config.timeout_seconds,
        )

    return {
        "status": "passed",
        "vault_addr": config.address.rstrip("/"),
        "mount": config.mount.strip("/"),
        "seeded_names": list(LOCAL_VAULT_SECRET_NAMES),
        "seeded_count": len(LOCAL_VAULT_SECRET_NAMES),
    }


def _config_from_env(env: Mapping[str, str]) -> LocalVaultBootstrapConfig:
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
    return LocalVaultBootstrapConfig(
        address=address,
        mount=mount,
        token_env=token_env,
        token=_optional(env, token_env) or DEFAULT_LOCAL_VAULT_TOKEN,
        timeout_seconds=_int_env(env, TIMEOUT_ENV, 3),
        allow_nonlocal=_enabled(env.get(ALLOW_NONLOCAL_ENV, "")),
    )


def _validate_config(config: LocalVaultBootstrapConfig) -> None:
    if not config.address.strip():
        raise LocalVaultBootstrapError("local Vault address is required")
    if not config.mount.strip() or "/" in config.mount.strip("/"):
        raise LocalVaultBootstrapError("local Vault mount must be a single path segment")
    if not config.token.strip():
        raise LocalVaultBootstrapError("local Vault token is required")
    if config.timeout_seconds <= 0:
        raise LocalVaultBootstrapError("local Vault timeout must be positive")
    parsed = parse.urlparse(config.address)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        if not config.allow_nonlocal:
            raise LocalVaultBootstrapError(
                "bootstrap_local_vault.py only writes to loopback HTTP Vault addresses by default"
            )


def _kv2_secret_url(config: LocalVaultBootstrapConfig, secret_name: str) -> str:
    mount = config.mount.strip("/")
    encoded_path = "/".join(parse.quote(part, safe="") for part in secret_name.split("/"))
    return f"{config.address.rstrip('/')}/v1/{mount}/data/{encoded_path}"


def _secret_value(secret_name: str) -> str:
    digest = hashlib.sha256(f"hallu-defense-local-vault:{secret_name}".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def _urllib_request_json(
    method: str,
    url: str,
    headers: Mapping[str, str],
    payload: Mapping[str, object] | None,
    timeout_seconds: int,
) -> Mapping[str, object]:
    raw_payload = None if payload is None else json.dumps(payload).encode("utf-8")
    vault_request = request.Request(
        url,
        data=raw_payload,
        headers={"Content-Type": "application/json", **dict(headers)},
        method=method,
    )
    try:
        with request.urlopen(vault_request, timeout=timeout_seconds) as response:
            response_body = response.read()
    except error.HTTPError as exc:
        raise LocalVaultBootstrapError(f"local Vault request failed with HTTP {exc.code}") from exc
    except (error.URLError, TimeoutError, OSError) as exc:
        raise LocalVaultBootstrapError("local Vault request failed") from exc

    if not response_body.strip():
        return {}
    try:
        parsed: object = json.loads(response_body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LocalVaultBootstrapError("local Vault response was not valid JSON") from exc
    if not isinstance(parsed, Mapping):
        raise LocalVaultBootstrapError("local Vault response must be a JSON object")
    return parsed


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
        raise LocalVaultBootstrapError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise LocalVaultBootstrapError(f"{name} must be positive")
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
