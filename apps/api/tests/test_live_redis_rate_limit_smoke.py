from __future__ import annotations

from threading import Lock

from scripts.dev import live_redis_rate_limit_smoke as smoke


class SharedLimiterState:
    def __init__(self) -> None:
        self.counts: dict[tuple[str, str, str], int] = {}
        self.lock = Lock()
        self.health_checks = 0


class FakeDistributedLimiter:
    def __init__(self, state: SharedLimiterState) -> None:
        self._state = state

    def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool:
        key = (tenant_id, subject_id, tool_name)
        with self._state.lock:
            current = self._state.counts.get(key, 0) + 1
            self._state.counts[key] = current
            return current <= smoke.MAX_REQUESTS

    def health_check(self) -> None:
        self._state.health_checks += 1


def test_live_redis_rate_limit_smoke_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert smoke.ENABLED_ENV in str(result["reason"])


def test_live_smoke_exercises_two_limiters_concurrency_tenant_and_expiry() -> None:
    state = SharedLimiterState()

    def expire_window(_seconds: float) -> None:
        with state.lock:
            state.counts.clear()

    result = smoke.run_live_smoke(
        limiter_factory=lambda: FakeDistributedLimiter(state),
        run_id="unit",
        sleep=expire_window,
    )

    assert result == {
        "status": "passed",
        "replica_count": 2,
        "burst_requests": smoke.BURST_REQUESTS,
        "allowed_count": smoke.MAX_REQUESTS,
        "blocked_count": smoke.BURST_REQUESTS - smoke.MAX_REQUESTS,
        "tenant_isolated": True,
        "window_expired": True,
    }
    assert state.health_checks == 2
