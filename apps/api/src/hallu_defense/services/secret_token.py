from __future__ import annotations

import hmac
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
)

DEFAULT_SECRET_TOKEN_CACHE_TTL_SECONDS = 5.0
DEFAULT_SECRET_TOKEN_FAILURE_BACKOFF_SECONDS = 1.0
DEFAULT_PREVIOUS_TOKEN_GRACE_SECONDS = 65.0
MIN_BEARER_TOKEN_BYTES = 32
# The worker accepts at most a 4096-byte Authorization header. Reserve the
# exact seven ASCII bytes used by ``Bearer `` so every valid shared token is
# representable on the wire.
MAX_BEARER_TOKEN_BYTES = 4096 - len("Bearer ")
BEARER_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~+/-]+={0,2}$")


@dataclass(frozen=True)
class _CachedToken:
    value: str
    expires_at: float


class RotatingSecretTokenVerifier:
    """Short-lived, single-flight SecretManager token verifier."""

    def __init__(
        self,
        secret_manager: SecretManager,
        *,
        secret_name: str,
        cache_ttl_seconds: float = DEFAULT_SECRET_TOKEN_CACHE_TTL_SECONDS,
        failure_backoff_seconds: float = DEFAULT_SECRET_TOKEN_FAILURE_BACKOFF_SECONDS,
        previous_token_grace_seconds: float = DEFAULT_PREVIOUS_TOKEN_GRACE_SECONDS,
        minimum_token_bytes: int = MIN_BEARER_TOKEN_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        normalized_name = secret_name.strip()
        if not normalized_name:
            raise ValueError("Token verifier secret name must be configured.")
        if not 0 < cache_ttl_seconds <= 60:
            raise ValueError("Token verifier cache TTL must be in (0, 60].")
        if not 0 < failure_backoff_seconds <= 60:
            raise ValueError("Token verifier failure backoff must be in (0, 60].")
        if not 0 < previous_token_grace_seconds <= 300:
            raise ValueError("Previous-token grace must be in (0, 300].")
        if not 1 <= minimum_token_bytes <= MAX_BEARER_TOKEN_BYTES:
            raise ValueError("Token verifier minimum length is invalid.")
        self._secret_manager = secret_manager
        self._secret_name = normalized_name
        self._cache_ttl_seconds = cache_ttl_seconds
        self._failure_backoff_seconds = failure_backoff_seconds
        self._previous_token_grace_seconds = previous_token_grace_seconds
        self._minimum_token_bytes = minimum_token_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._cached: _CachedToken | None = None
        self._previous: _CachedToken | None = None
        self._failed_until = 0.0
        self._next_mismatch_refresh_at = 0.0

    def matches(self, candidate: str) -> bool:
        if not candidate:
            return False
        try:
            validate_bearer_token(candidate, minimum_token_bytes=1)
        except ValueError:
            return False
        current, previous = self._expected_tokens(force_refresh=False)
        if _matches_either(candidate, current, previous):
            return True
        current, previous = self._expected_tokens(force_refresh=True)
        return _matches_either(candidate, current, previous)

    def _expected_tokens(
        self,
        *,
        force_refresh: bool,
    ) -> tuple[str | None, str | None]:
        now = self._clock()
        with self._lock:
            cached = self._cached
            current_value = (
                cached.value
                if cached is not None and cached.expires_at > now
                else None
            )
            cached_is_valid = current_value is not None
            previous = self._previous
            if previous is not None and previous.expires_at <= now:
                self._previous = None
                previous = None
            if cached_is_valid and not force_refresh:
                return current_value, previous.value if previous is not None else None
            if force_refresh and cached_is_valid:
                if (
                    self._failed_until > now
                    or self._next_mismatch_refresh_at > now
                ):
                    return current_value, previous.value if previous is not None else None
                self._next_mismatch_refresh_at = now + self._failure_backoff_seconds
            elif self._failed_until > now:
                self._cached = None
                self._previous = None
                return None, None
            try:
                expected = self._secret_manager.get_secret(self._secret_name).reveal()
            except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
                self._failed_until = now + self._failure_backoff_seconds
                if cached_is_valid:
                    return current_value, previous.value if previous is not None else None
                self._cached = None
                self._previous = None
                return None, None
            try:
                validate_bearer_token(
                    expected,
                    minimum_token_bytes=self._minimum_token_bytes,
                )
            except ValueError:
                self._failed_until = now + self._failure_backoff_seconds
                if cached_is_valid:
                    return current_value, previous.value if previous is not None else None
                self._cached = None
                self._previous = None
                return None, None
            self._failed_until = 0.0
            self._next_mismatch_refresh_at = max(
                self._next_mismatch_refresh_at,
                now + self._failure_backoff_seconds,
            )
            if cached is not None and not hmac.compare_digest(cached.value, expected):
                self._previous = _CachedToken(
                    value=cached.value,
                    expires_at=now + self._previous_token_grace_seconds,
                )
            self._cached = _CachedToken(
                value=expected,
                expires_at=now + self._cache_ttl_seconds,
            )
            previous = self._previous
            return expected, previous.value if previous is not None else None


def validate_bearer_token(
    value: str,
    *,
    minimum_token_bytes: int = MIN_BEARER_TOKEN_BYTES,
) -> None:
    try:
        payload = value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Bearer token has an invalid format.") from None
    if (
        not minimum_token_bytes <= len(payload) <= MAX_BEARER_TOKEN_BYTES
        or BEARER_TOKEN_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("Bearer token has an invalid format.")


def _matches_either(
    candidate: str,
    current: str | None,
    previous: str | None,
) -> bool:
    return (current is not None and hmac.compare_digest(candidate, current)) or (
        previous is not None and hmac.compare_digest(candidate, previous)
    )
