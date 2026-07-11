from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import pytest

from hallu_defense.services.secret_token import (
    MAX_BEARER_TOKEN_BYTES,
    RotatingSecretTokenVerifier,
    validate_bearer_token,
)
from hallu_defense.services.secrets import SecretNotFoundError, SecretValue

FIRST_TOKEN = "a" * 32
SECOND_TOKEN = "b" * 32


class RotatingManager:
    def __init__(self, value: str) -> None:
        self.value = value
        self.calls = 0
        self.fail = False
        self._lock = Lock()

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert name == "observability/metrics-token"
        assert field == "value"
        with self._lock:
            self.calls += 1
        if self.fail:
            raise SecretNotFoundError("sensitive-vault-error")
        return SecretValue(name=name, _value=self.value)


def test_secret_token_verifier_single_flights_concurrent_invalid_requests() -> None:
    manager = RotatingManager(FIRST_TOKEN)
    verifier = RotatingSecretTokenVerifier(
        manager,
        secret_name="observability/metrics-token",
        clock=lambda: 1000.0,
    )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(verifier.matches, [f"wrong-{i}" for i in range(64)]))

    assert results == [False] * 64
    assert manager.calls == 1


def test_secret_token_verifier_observes_rotation_after_bounded_ttl() -> None:
    now = 1000.0
    manager = RotatingManager(FIRST_TOKEN)
    verifier = RotatingSecretTokenVerifier(
        manager,
        secret_name="observability/metrics-token",
        cache_ttl_seconds=5,
        clock=lambda: now,
    )

    assert verifier.matches(FIRST_TOKEN) is True
    manager.value = SECOND_TOKEN
    now = 1004.0
    assert verifier.matches(SECOND_TOKEN) is True
    assert verifier.matches(FIRST_TOKEN) is True
    now = 1006.0
    assert verifier.matches(SECOND_TOKEN) is True
    assert manager.calls == 2


def test_secret_token_verifier_fails_closed_after_cache_expiry() -> None:
    now = 1000.0
    manager = RotatingManager(FIRST_TOKEN)
    verifier = RotatingSecretTokenVerifier(
        manager,
        secret_name="observability/metrics-token",
        cache_ttl_seconds=5,
        clock=lambda: now,
    )
    assert verifier.matches(FIRST_TOKEN) is True
    manager.fail = True
    now = 1006.0

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(verifier.matches, [FIRST_TOKEN] * 64))

    assert results == [False] * 64
    assert manager.calls == 2


def test_secret_token_verifier_retries_after_failure_backoff() -> None:
    now = 1000.0
    manager = RotatingManager(FIRST_TOKEN)
    manager.fail = True
    verifier = RotatingSecretTokenVerifier(
        manager,
        secret_name="observability/metrics-token",
        failure_backoff_seconds=1,
        clock=lambda: now,
    )

    assert verifier.matches(FIRST_TOKEN) is False
    now = 1000.5
    assert verifier.matches(FIRST_TOKEN) is False
    manager.fail = False
    now = 1001.1
    assert verifier.matches(FIRST_TOKEN) is True
    assert manager.calls == 2


def test_secret_token_verifier_rejects_weak_rotated_secret_without_caching() -> None:
    now = 1000.0
    manager = RotatingManager(FIRST_TOKEN)
    verifier = RotatingSecretTokenVerifier(
        manager,
        secret_name="observability/metrics-token",
        cache_ttl_seconds=5,
        failure_backoff_seconds=1,
        clock=lambda: now,
    )
    assert verifier.matches(FIRST_TOKEN) is True

    manager.value = "x"
    now = 1006.0
    assert verifier.matches("x") is False
    assert verifier.matches(FIRST_TOKEN) is False
    manager.value = SECOND_TOKEN
    now = 1007.1
    assert verifier.matches(SECOND_TOKEN) is True
    assert manager.calls == 3


def test_secret_token_verifier_rejects_malformed_candidates_without_secret_io() -> None:
    manager = RotatingManager(FIRST_TOKEN)
    verifier = RotatingSecretTokenVerifier(
        manager,
        secret_name="observability/metrics-token",
        clock=lambda: 1000.0,
    )

    assert verifier.matches("inválido") is False
    assert verifier.matches("a" * (MAX_BEARER_TOKEN_BYTES + 1)) is False
    assert manager.calls == 0


def test_bearer_token_wire_limit_matches_authorization_header_capacity() -> None:
    validate_bearer_token("a" * MAX_BEARER_TOKEN_BYTES)

    with pytest.raises(ValueError):
        validate_bearer_token("a" * (MAX_BEARER_TOKEN_BYTES + 1))
