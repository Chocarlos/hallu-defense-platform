from __future__ import annotations

import hashlib
import re
import ssl
import time
from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import Protocol, cast
from urllib.parse import urlparse

from redis import Redis
from redis.exceptions import RedisError

from hallu_defense.config import (
    PRODUCTION_LIKE_ENVIRONMENTS,
    RateLimitConfigurationError,
    Settings,
    validate_rate_limit_settings,
)
from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
)

RATE_LIMIT_BACKEND_MEMORY = "memory"
RATE_LIMIT_BACKEND_REDIS = "redis"
RATE_LIMIT_KEY_PREFIX = "hallu-defense:tool-validation-rate-limit:v1:"

# A single-key script keeps the increment and expiry atomic across API replicas.
# We intentionally do not retry a timed-out call: Redis may already have counted
# it, and failing closed is safer than creating an unbounded approval request.
REDIS_FIXED_WINDOW_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
if current > tonumber(ARGV[1]) then
  return 0
end
return 1
""".strip()


class RateLimitUnavailableError(RuntimeError):
    pass


class RateLimitProtocolError(RateLimitUnavailableError):
    pass


class ToolValidationRateLimitBackend(Protocol):
    def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool: ...

    def health_check(self) -> None: ...


class RedisRateLimitClient(Protocol):
    def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object: ...

    def ping(self) -> bool: ...


RedisClientFactory = Callable[[str, float, Path | None], RedisRateLimitClient]


class ToolValidationRateLimiter:
    """Thread-safe local limiter for development and deterministic unit tests."""

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        _validate_limits(max_requests=max_requests, window_seconds=window_seconds)
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._clock = clock
        self._windows: dict[tuple[str, str, str], tuple[float, int]] = {}
        self._lock = Lock()

    def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool:
        key = _normalized_scope(tenant_id, subject_id, tool_name)
        now = self._clock()
        with self._lock:
            window_started_at, count = self._windows.get(key, (now, 0))
            if now - window_started_at >= self._window_seconds:
                window_started_at, count = now, 0
            if count >= self._max_requests:
                return False
            self._windows[key] = (window_started_at, count + 1)
            return True

    def health_check(self) -> None:
        return None


class RedisToolValidationRateLimiter:
    def __init__(
        self,
        *,
        client: RedisRateLimitClient,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        _validate_limits(max_requests=max_requests, window_seconds=window_seconds)
        self._client = client
        self._max_requests = max_requests
        self._window_milliseconds = window_seconds * 1000

    def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool:
        key = _redis_scope_key(tenant_id, subject_id, tool_name)
        try:
            result = self._client.eval(
                REDIS_FIXED_WINDOW_SCRIPT,
                1,
                key,
                self._max_requests,
                self._window_milliseconds,
            )
        except RedisError:
            raise RateLimitUnavailableError(
                "Distributed rate limit backend is unavailable."
            ) from None
        if type(result) is not int or result not in {0, 1}:
            raise RateLimitProtocolError("Distributed rate limit backend returned an invalid response.")
        return result == 1

    def health_check(self) -> None:
        try:
            healthy = self._client.ping()
        except RedisError:
            raise RateLimitUnavailableError(
                "Distributed rate limit backend is unavailable."
            ) from None
        if healthy is not True:
            raise RateLimitProtocolError("Distributed rate limit backend returned an invalid response.")


def create_tool_validation_rate_limiter(
    settings: Settings,
    secret_manager: SecretManager,
    *,
    redis_client_factory: RedisClientFactory | None = None,
) -> ToolValidationRateLimitBackend:
    validate_rate_limit_settings(settings)
    backend = settings.tool_validation_rate_limit_backend.strip().lower()
    if backend == RATE_LIMIT_BACKEND_MEMORY:
        if settings.environment.strip().lower() in PRODUCTION_LIKE_ENVIRONMENTS:
            raise RateLimitConfigurationError(
                "Production and staging must use the Redis tool-validation rate limit backend."
            )
        return ToolValidationRateLimiter(
            max_requests=settings.tool_validation_rate_limit_max_requests,
            window_seconds=settings.tool_validation_rate_limit_window_seconds,
        )
    if backend != RATE_LIMIT_BACKEND_REDIS:
        raise RateLimitConfigurationError("Unsupported tool-validation rate limit backend.")

    redis_url = _resolve_redis_url(settings, secret_manager)
    _validate_redis_url(redis_url, settings)
    client_factory = redis_client_factory or _create_redis_client
    try:
        client = client_factory(
            redis_url,
            settings.tool_validation_rate_limit_redis_timeout_seconds,
            settings.tool_validation_rate_limit_redis_ca_path,
        )
    except (RedisError, OSError, TypeError, ValueError):
        raise RateLimitConfigurationError(
            "Tool-validation Redis client could not be configured."
        ) from None
    return RedisToolValidationRateLimiter(
        client=client,
        max_requests=settings.tool_validation_rate_limit_max_requests,
        window_seconds=settings.tool_validation_rate_limit_window_seconds,
    )


def _resolve_redis_url(settings: Settings, secret_manager: SecretManager) -> str:
    direct_url = settings.tool_validation_rate_limit_redis_url
    if direct_url is not None:
        return direct_url.strip()
    try:
        value = secret_manager.get_secret(
            settings.tool_validation_rate_limit_redis_url_secret_name
        ).reveal()
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL secret is unavailable."
        ) from None
    return value.strip()


def _validate_redis_url(redis_url: str, settings: Settings) -> None:
    try:
        parsed = urlparse(redis_url)
        port = parsed.port
    except ValueError:
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL is invalid."
        ) from None
    environment = settings.environment.strip().lower()
    if (
        parsed.scheme not in {"redis", "rediss"}
        or parsed.hostname is None
        or any(character.isspace() for character in redis_url)
    ):
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL must be an absolute redis:// or rediss:// URL."
        )
    if port is not None and not 1 <= port <= 65_535:
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL port must be between 1 and 65535."
        )
    if parsed.path and re.fullmatch(r"/(?:0|[1-9][0-9]*)", parsed.path) is None:
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL database path must be canonical."
        )
    if parsed.query or parsed.fragment:
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL must not contain query parameters or fragments."
        )
    if environment in PRODUCTION_LIKE_ENVIRONMENTS and parsed.scheme != "rediss":
        raise RateLimitConfigurationError(
            "Tool-validation Redis URL must use rediss:// in production and staging."
        )


def _create_redis_client(
    redis_url: str,
    timeout_seconds: float,
    ca_path: Path | None,
) -> RedisRateLimitClient:
    options: dict[str, object] = {
        "socket_connect_timeout": timeout_seconds,
        "socket_timeout": timeout_seconds,
        "retry_on_timeout": False,
        "decode_responses": False,
    }
    if urlparse(redis_url).scheme == "rediss":
        options["ssl_cert_reqs"] = ssl.CERT_REQUIRED
        if ca_path is not None:
            options["ssl_ca_certs"] = str(ca_path)
    return cast(RedisRateLimitClient, Redis.from_url(redis_url, **options))


def _redis_scope_key(tenant_id: str, subject_id: str, tool_name: str) -> str:
    scope = _normalized_scope(tenant_id, subject_id, tool_name)
    digest = hashlib.sha256()
    for value in scope:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, byteorder="big"))
        digest.update(encoded)
    return f"{RATE_LIMIT_KEY_PREFIX}{digest.hexdigest()}"


def _normalized_scope(tenant_id: str, subject_id: str, tool_name: str) -> tuple[str, str, str]:
    normalized_tool = tool_name.strip().lower()
    if not tenant_id or not subject_id or not normalized_tool:
        raise ValueError("Rate limit tenant, subject, and tool scope values must be non-empty.")
    return tenant_id, subject_id, normalized_tool


def _validate_limits(*, max_requests: int, window_seconds: int) -> None:
    if max_requests <= 0:
        raise ValueError("max_requests must be positive.")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive.")
