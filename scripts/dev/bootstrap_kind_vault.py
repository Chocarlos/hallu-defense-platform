"""Generate and seed kind-only provider/metrics credentials directly into TLS Vault."""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets as secret_generator
import ssl
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib import parse

ADDR_ENV = "HALLU_DEFENSE_KIND_VAULT_ADDR"
CA_PATH_ENV = "HALLU_DEFENSE_KIND_VAULT_CA_PATH"
TOKEN_PATH_ENV = "HALLU_DEFENSE_KIND_VAULT_TOKEN_PATH"
PROVIDER_SECRET_NAME_ENV = "HALLU_DEFENSE_KIND_PROVIDER_SECRET_NAME"
METRICS_SECRET_NAME_ENV = "HALLU_DEFENSE_KIND_METRICS_SECRET_NAME"
APPROVAL_COMMITMENT_SECRET_NAME_ENV = (
    "HALLU_DEFENSE_KIND_APPROVAL_COMMITMENT_SECRET_NAME"
)
SEED_CORE_CREDENTIALS_ENV = "HALLU_DEFENSE_KIND_VAULT_SEED_CORE_CREDENTIALS"
REDIS_SECRET_NAME_ENV = "HALLU_DEFENSE_KIND_REDIS_SECRET_NAME"
REDIS_URL_PATH_ENV = "HALLU_DEFENSE_KIND_REDIS_URL_PATH"
READY_MARKER_PATH_ENV = "HALLU_DEFENSE_KIND_READY_MARKER_PATH"
WAIT_SECONDS_ENV = "HALLU_DEFENSE_KIND_VAULT_WAIT_SECONDS"
DEFAULT_WAIT_SECONDS = 300
MAX_SECRET_FILE_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,255}$")


class KindVaultBootstrapError(RuntimeError):
    pass


@dataclass(frozen=True)
class KindVaultBootstrapConfig:
    address: str
    ca_path: Path
    token_path: Path
    provider_secret_name: str | None
    metrics_secret_name: str | None
    approval_commitment_secret_name: str | None
    seed_core_credentials: bool = True
    redis_secret_name: str | None = None
    redis_url_path: Path | None = None
    ready_marker_path: Path | None = None
    wait_seconds: int = DEFAULT_WAIT_SECONDS
    request_timeout_seconds: float = 3.0


RequestJson = Callable[
    [str, str, Mapping[str, str], Mapping[str, object] | None, float, Path],
    Mapping[str, object],
]


def run_from_env(
    env: Mapping[str, str] | None = None,
    *,
    request_json: RequestJson | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    effective_env = env if env is not None else os.environ
    seed_core_credentials = _boolean(
        effective_env,
        SEED_CORE_CREDENTIALS_ENV,
        default=True,
    )
    provider_secret_name = _optional(effective_env, PROVIDER_SECRET_NAME_ENV)
    metrics_secret_name = _optional(effective_env, METRICS_SECRET_NAME_ENV)
    config = KindVaultBootstrapConfig(
        address=_required(effective_env, ADDR_ENV),
        ca_path=Path(_required(effective_env, CA_PATH_ENV)),
        token_path=Path(_required(effective_env, TOKEN_PATH_ENV)),
        provider_secret_name=provider_secret_name,
        metrics_secret_name=metrics_secret_name,
        approval_commitment_secret_name=_optional(
            effective_env,
            APPROVAL_COMMITMENT_SECRET_NAME_ENV,
        ),
        seed_core_credentials=seed_core_credentials,
        redis_secret_name=_optional(effective_env, REDIS_SECRET_NAME_ENV),
        redis_url_path=(
            Path(value)
            if (value := _optional(effective_env, REDIS_URL_PATH_ENV)) is not None
            else None
        ),
        ready_marker_path=(
            Path(value)
            if (value := _optional(effective_env, READY_MARKER_PATH_ENV)) is not None
            else None
        ),
        wait_seconds=_positive_int(effective_env, WAIT_SECONDS_ENV, DEFAULT_WAIT_SECONDS),
    )
    return bootstrap_kind_vault(
        config,
        request_json=request_json,
        monotonic=monotonic,
        sleep=sleep,
    )


def bootstrap_kind_vault(
    config: KindVaultBootstrapConfig,
    *,
    request_json: RequestJson | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    credential_factory: Callable[[], str] | None = None,
) -> dict[str, object]:
    _validate_config(config)
    vault_credential = _read_secret_file(config.token_path, "Vault token")
    requester = request_json or _https_request_json
    deadline = monotonic() + config.wait_seconds
    health_url = f"{config.address.rstrip('/')}/v1/sys/health"

    while True:
        try:
            requester(
                "GET",
                health_url,
                {},
                None,
                config.request_timeout_seconds,
                config.ca_path,
            )
            break
        except KindVaultBootstrapError as exc:
            if monotonic() >= deadline:
                raise KindVaultBootstrapError(
                    "kind Vault did not become ready before the deadline"
                ) from exc
            sleep(1.0)

    secrets_to_seed: list[tuple[str, str]] = []
    if config.seed_core_credentials:
        assert config.provider_secret_name is not None
        assert config.metrics_secret_name is not None
        assert config.approval_commitment_secret_name is not None
        factory = credential_factory or (lambda: secret_generator.token_urlsafe(32))
        provider_credential = _generated_credential(factory())
        metrics_credential = _generated_credential(factory())
        while metrics_credential == provider_credential:
            metrics_credential = _generated_credential(factory())
        approval_commitment_key = _generated_credential(factory())
        while approval_commitment_key in {provider_credential, metrics_credential}:
            approval_commitment_key = _generated_credential(factory())
        secrets_to_seed.extend(
            (
                (config.provider_secret_name, provider_credential),
                (config.metrics_secret_name, metrics_credential),
                (
                    config.approval_commitment_secret_name,
                    approval_commitment_key,
                ),
            )
        )
    if config.redis_secret_name is not None and config.redis_url_path is not None:
        redis_url = _read_secret_file(config.redis_url_path, "Redis URL")
        _validate_kind_redis_url(redis_url)
        secrets_to_seed.append((config.redis_secret_name, redis_url))
    for secret_name, secret_value in secrets_to_seed:
        encoded_name = "/".join(
            parse.quote(segment, safe="") for segment in secret_name.split("/")
        )
        requester(
            "PUT",
            f"{config.address.rstrip('/')}/v1/secret/data/{encoded_name}",
            {"X-Vault-Token": vault_credential},
            {"data": {"value": secret_value}},
            config.request_timeout_seconds,
            config.ca_path,
        )
    if config.ready_marker_path is not None:
        try:
            config.ready_marker_path.write_text("ready\n", encoding="utf-8")
        except OSError as exc:
            raise KindVaultBootstrapError("kind ready marker could not be written") from exc
    if config.redis_url_path is not None:
        try:
            config.redis_url_path.unlink()
        except OSError as exc:
            raise KindVaultBootstrapError(
                "kind Redis URL file could not be removed after Vault seeding"
            ) from exc
    return {
        "status": "passed",
        "vault_addr": config.address.rstrip("/"),
        "seeded_names": [name for name, _value in secrets_to_seed],
        "seeded_count": len(secrets_to_seed),
    }


def _validate_config(config: KindVaultBootstrapConfig) -> None:
    parsed = parse.urlparse(config.address)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise KindVaultBootstrapError("kind Vault address must be an HTTPS origin")
    if config.wait_seconds <= 0 or config.request_timeout_seconds <= 0:
        raise KindVaultBootstrapError("kind Vault timeouts must be positive")
    if not config.ca_path.is_file():
        raise KindVaultBootstrapError("kind Vault CA certificate is unavailable")
    if config.seed_core_credentials and (
        config.provider_secret_name is None
        or config.metrics_secret_name is None
        or config.approval_commitment_secret_name is None
    ):
        raise KindVaultBootstrapError(
            "provider, metrics, and approval commitment secret names are required "
            "when core credential seeding is enabled"
        )
    if (config.redis_secret_name is None) != (config.redis_url_path is None):
        raise KindVaultBootstrapError(
            "kind Redis secret name and URL path must be configured together"
        )
    if not config.seed_core_credentials and config.redis_secret_name is None:
        raise KindVaultBootstrapError("kind Vault bootstrap has no configured secret targets")
    named_targets = (
        (config.provider_secret_name, "provider"),
        (config.metrics_secret_name, "metrics"),
        (config.approval_commitment_secret_name, "approval commitment"),
        (config.redis_secret_name, "Redis"),
    )
    for name, label in named_targets:
        if name is None:
            continue
        if (
            SECRET_NAME_RE.fullmatch(name) is None
            or name.startswith("/")
            or name.endswith("/")
            or "//" in name
            or any(segment in {".", ".."} for segment in name.split("/"))
        ):
            raise KindVaultBootstrapError(f"{label} secret name is invalid")
    if config.redis_url_path is not None and not config.redis_url_path.is_file():
        raise KindVaultBootstrapError("kind Redis URL file is unavailable")
    if config.ready_marker_path is not None:
        if config.redis_url_path is None:
            raise KindVaultBootstrapError(
                "kind ready marker is allowed only for Redis Vault seeding"
            )
        if not config.ready_marker_path.is_absolute() or not config.ready_marker_path.parent.is_dir():
            raise KindVaultBootstrapError("kind ready marker parent is unavailable")


def _validate_kind_redis_url(value: str) -> None:
    try:
        parsed = parse.urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise KindVaultBootstrapError("kind Redis URL is invalid") from exc
    if (
        parsed.scheme != "rediss"
        or parsed.username != "hallu-rate-limiter"
        or parsed.password is None
        or re.fullmatch(r"[a-f0-9]{64}", parsed.password) is None
        or parsed.hostname is None
        or port != 6379
        or parsed.path != "/0"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise KindVaultBootstrapError(
            "kind Redis URL must be canonical TLS with the dedicated ACL user"
        )


def _read_secret_file(path: Path, label: str) -> str:
    try:
        with path.open("rb") as stream:
            payload = stream.read(MAX_SECRET_FILE_BYTES + 1)
    except OSError as exc:
        raise KindVaultBootstrapError(f"{label} file is unavailable") from exc
    if len(payload) > MAX_SECRET_FILE_BYTES:
        raise KindVaultBootstrapError(f"{label} file exceeds the safety limit")
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise KindVaultBootstrapError(f"{label} file is not UTF-8") from exc
    if not value:
        raise KindVaultBootstrapError(f"{label} file is empty")
    return value


def _generated_credential(value: str) -> str:
    if len(value) < 32 or value.strip() != value:
        raise KindVaultBootstrapError("generated kind Vault credential is invalid")
    return value


def _https_request_json(
    method: str,
    url: str,
    headers: Mapping[str, str],
    payload: Mapping[str, object] | None,
    timeout_seconds: float,
    ca_path: Path,
) -> Mapping[str, object]:
    parsed = parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise KindVaultBootstrapError("kind Vault request URL must use HTTPS")
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_headers = {"Accept": "application/json", **dict(headers)}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    context = ssl.create_default_context(cafile=str(ca_path))
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        port=parsed.port or 443,
        timeout=timeout_seconds,
        context=context,
    )
    request_path = parsed.path or "/"
    if parsed.query:
        request_path = f"{request_path}?{parsed.query}"
    try:
        connection.request(method, request_path, body=body, headers=request_headers)
        response = connection.getresponse()
        raw_response = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
        raise KindVaultBootstrapError("kind Vault HTTPS request failed") from exc
    finally:
        connection.close()
    if len(raw_response) > MAX_RESPONSE_BYTES:
        raise KindVaultBootstrapError("kind Vault response exceeded the 1 MiB safety limit")
    if not 200 <= response.status < 300:
        raise KindVaultBootstrapError(
            f"kind Vault HTTPS request failed with status {response.status}"
        )
    if not raw_response.strip():
        return {}
    try:
        decoded: object = json.loads(raw_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KindVaultBootstrapError("kind Vault response was not valid JSON") from exc
    if not isinstance(decoded, Mapping):
        raise KindVaultBootstrapError("kind Vault response must be a JSON object")
    return decoded


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if value is None or not value.strip():
        raise KindVaultBootstrapError(f"{name} is required")
    return value.strip()


def _optional(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _boolean(
    env: Mapping[str, str],
    name: str,
    *,
    default: bool,
) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise KindVaultBootstrapError(f"{name} must be a boolean")


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise KindVaultBootstrapError(f"{name} must be an integer") from exc
    if value <= 0:
        raise KindVaultBootstrapError(f"{name} must be positive")
    return value


def main(argv: Sequence[str] | None = None, *, env: Mapping[str, str] | None = None) -> int:
    _ = argv
    try:
        result = run_from_env(env)
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
