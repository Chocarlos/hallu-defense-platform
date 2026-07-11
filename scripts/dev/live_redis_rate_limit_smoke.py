from __future__ import annotations

import json
import os
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

ROOT = Path(__file__).resolve().parents[2]
API_SRC = ROOT / "apps" / "api" / "src"
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))

from hallu_defense.config import Settings, validate_rate_limit_settings  # noqa: E402
from hallu_defense.services.rate_limit import (  # noqa: E402
    ToolValidationRateLimitBackend,
    create_tool_validation_rate_limiter,
)
from hallu_defense.services.secrets import SecretValue  # noqa: E402

ENABLED_ENV = "HALLU_DEFENSE_LIVE_REDIS_RATE_LIMIT_SMOKE_ENABLED"
REDIS_URL_ENV = "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL"
REDIS_CA_PATH_ENV = "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH"
REDIS_TIMEOUT_ENV = "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS"
MAX_REQUESTS = 7
BURST_REQUESTS = 32
WINDOW_SECONDS = 1


class UnusedSecretManager:
    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        del name, field
        raise AssertionError("The local live smoke must use its direct Redis URL.")


LimiterFactory = Callable[[], ToolValidationRateLimitBackend]


def run_from_env(env: Mapping[str, str] | None = None) -> dict[str, object]:
    effective_env = os.environ if env is None else env
    if effective_env.get(ENABLED_ENV, "").strip().lower() != "true":
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live Redis rate-limit smoke",
        }
    redis_url = effective_env.get(REDIS_URL_ENV, "").strip()
    if not redis_url:
        raise RuntimeError(f"{REDIS_URL_ENV} is required for the live Redis rate-limit smoke")
    ca_value = effective_env.get(REDIS_CA_PATH_ENV, "").strip()
    ca_path = Path(ca_value).resolve() if ca_value else None
    settings = Settings(
        environment="local",
        policy_version="live-redis-rate-limit-smoke",
        auth_required=False,
        allowed_workspace=ROOT,
        max_command_seconds=5,
        max_output_chars=1000,
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_max_requests=MAX_REQUESTS,
        tool_validation_rate_limit_window_seconds=WINDOW_SECONDS,
        tool_validation_rate_limit_redis_url=redis_url,
        tool_validation_rate_limit_redis_timeout_seconds=float(
            effective_env.get(REDIS_TIMEOUT_ENV, "1")
        ),
        tool_validation_rate_limit_redis_ca_path=ca_path,
    )
    validate_rate_limit_settings(settings)
    secret_manager = UnusedSecretManager()
    return run_live_smoke(
        limiter_factory=lambda: create_tool_validation_rate_limiter(
            settings,
            secret_manager,
        ),
        run_id=uuid.uuid4().hex,
    )


def run_live_smoke(
    *,
    limiter_factory: LimiterFactory,
    run_id: str,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    limiters = (limiter_factory(), limiter_factory())
    for limiter in limiters:
        limiter.health_check()

    scope = {
        "tenant_id": f"tenant-live-rate-limit-{run_id}",
        "subject_id": f"agent-live-rate-limit-{run_id}",
        "tool_name": "delete_repository",
    }
    barrier = Barrier(BURST_REQUESTS)

    def attempt(index: int) -> bool:
        barrier.wait()
        return limiters[index % len(limiters)].allow(**scope)

    with ThreadPoolExecutor(max_workers=BURST_REQUESTS) as executor:
        decisions = list(executor.map(attempt, range(BURST_REQUESTS)))
    allowed_count = decisions.count(True)
    if allowed_count != MAX_REQUESTS:
        raise RuntimeError("distributed rate limit admitted an unexpected request count")

    tenant_isolated = limiters[0].allow(
        tenant_id=f"tenant-live-rate-limit-isolated-{run_id}",
        subject_id=scope["subject_id"],
        tool_name=scope["tool_name"],
    )
    if not tenant_isolated:
        raise RuntimeError("distributed rate limit mixed tenant quota state")

    sleep(WINDOW_SECONDS + 0.1)
    if not limiters[1].allow(**scope):
        raise RuntimeError("distributed rate limit did not expire its window")

    return {
        "status": "passed",
        "replica_count": len(limiters),
        "burst_requests": BURST_REQUESTS,
        "allowed_count": allowed_count,
        "blocked_count": decisions.count(False),
        "tenant_isolated": tenant_isolated,
        "window_expired": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        result = run_from_env()
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed", "error_type": type(exc).__name__},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
