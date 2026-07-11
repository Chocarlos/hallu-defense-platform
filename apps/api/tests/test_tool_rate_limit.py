from __future__ import annotations

import re
import ssl
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Barrier, Lock
from typing import cast

import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from hallu_defense.api import routes
from hallu_defense.services import rate_limit as rate_limit_module
from hallu_defense.config import (
    RateLimitConfigurationError,
    Settings,
    load_settings,
    validate_rate_limit_settings,
)
from hallu_defense.main import app
from hallu_defense.services.metrics import PrometheusMetrics
from hallu_defense.services.rate_limit import (
    RATE_LIMIT_KEY_PREFIX,
    REDIS_FIXED_WINDOW_SCRIPT,
    RateLimitProtocolError,
    RateLimitUnavailableError,
    RedisRateLimitClient,
    RedisToolValidationRateLimiter,
    ToolValidationRateLimitBackend,
    ToolValidationRateLimiter,
    create_tool_validation_rate_limiter,
)
from hallu_defense.services.secrets import SecretNotFoundError, SecretValue


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "rate-limit-test",
        "auth_required": False,
        "allowed_workspace": Path.cwd(),
        "max_command_seconds": 5,
        "max_output_chars": 1000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@dataclass
class SharedRedisState:
    counts: dict[str, int] = field(default_factory=dict)
    expires_at_ms: dict[str, int] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock)


class AtomicFakeRedis:
    def __init__(
        self,
        state: SharedRedisState | None = None,
        *,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self.state = state or SharedRedisState()
        self._clock_ms = clock_ms or (lambda: 100_000)
        self.calls: list[tuple[str, int, tuple[str | int, ...]]] = []
        self.ping_result = True

    def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object:
        self.calls.append((script, numkeys, keys_and_args))
        key = cast(str, keys_and_args[0])
        max_requests = cast(int, keys_and_args[1])
        window_ms = cast(int, keys_and_args[2])
        now = int(self._clock_ms())
        with self.state.lock:
            if self.state.expires_at_ms.get(key, now + 1) <= now:
                self.state.counts.pop(key, None)
                self.state.expires_at_ms.pop(key, None)
            current = self.state.counts.get(key, 0) + 1
            self.state.counts[key] = current
            if current == 1:
                self.state.expires_at_ms[key] = now + window_ms
            return 1 if current <= max_requests else 0

    def ping(self) -> bool:
        return self.ping_result


class OutageRedis:
    def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object:
        del script, numkeys, keys_and_args
        raise RedisConnectionError("redis-password-must-not-leak")

    def ping(self) -> bool:
        raise RedisConnectionError("redis-password-must-not-leak")


class MalformedRedis:
    def eval(self, script: str, numkeys: int, *keys_and_args: str | int) -> object:
        del script, numkeys, keys_and_args
        return b"1"

    def ping(self) -> bool:
        return False


class StaticSecretManager:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.requested: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.requested.append(name)
        if field != "value" or name not in self.values:
            raise SecretNotFoundError("secret-value-must-not-leak")
        return SecretValue(name=name, _value=self.values[name])


class RecordingClientFactory:
    def __init__(self, client: RedisRateLimitClient) -> None:
        self.client = client
        self.calls: list[tuple[str, float, Path | None]] = []

    def __call__(
        self,
        redis_url: str,
        timeout_seconds: float,
        ca_path: Path | None,
    ) -> RedisRateLimitClient:
        self.calls.append((redis_url, timeout_seconds, ca_path))
        return self.client


def test_in_memory_rate_limiter_is_atomic_between_threads() -> None:
    limiter = ToolValidationRateLimiter(
        max_requests=7,
        window_seconds=60,
        clock=lambda: 100.0,
    )
    barrier = Barrier(32)

    def attempt() -> bool:
        barrier.wait()
        return limiter.allow(
            tenant_id="tenant-a",
            subject_id="agent-a",
            tool_name="delete_repository",
        )

    with ThreadPoolExecutor(max_workers=32) as executor:
        decisions = list(executor.map(lambda _: attempt(), range(32)))

    assert decisions.count(True) == 7
    assert decisions.count(False) == 25


def test_two_redis_limiter_instances_share_one_atomic_quota() -> None:
    state = SharedRedisState()
    first = RedisToolValidationRateLimiter(
        client=AtomicFakeRedis(state),
        max_requests=1,
        window_seconds=60,
    )
    second = RedisToolValidationRateLimiter(
        client=AtomicFakeRedis(state),
        max_requests=1,
        window_seconds=60,
    )
    scope = {
        "tenant_id": "tenant-a",
        "subject_id": "agent-a",
        "tool_name": "delete_repository",
    }

    assert first.allow(**scope) is True
    assert second.allow(**scope) is False


def test_redis_rate_limit_scope_isolates_tenant_subject_and_tool() -> None:
    limiter = RedisToolValidationRateLimiter(
        client=AtomicFakeRedis(),
        max_requests=1,
        window_seconds=60,
    )

    assert limiter.allow(tenant_id="tenant-a", subject_id="agent-a", tool_name="lookup")
    assert not limiter.allow(
        tenant_id="tenant-a",
        subject_id="agent-a",
        tool_name=" LOOKUP ",
    )
    assert limiter.allow(tenant_id="tenant-b", subject_id="agent-a", tool_name="lookup")
    assert limiter.allow(tenant_id="tenant-a", subject_id="agent-b", tool_name="lookup")
    assert limiter.allow(tenant_id="tenant-a", subject_id="agent-a", tool_name="summarize")


def test_redis_rate_limiter_is_atomic_during_cross_instance_burst() -> None:
    state = SharedRedisState()
    limiters = [
        RedisToolValidationRateLimiter(
            client=AtomicFakeRedis(state),
            max_requests=11,
            window_seconds=60,
        )
        for _ in range(2)
    ]
    barrier = Barrier(40)

    def attempt(index: int) -> bool:
        barrier.wait()
        return limiters[index % 2].allow(
            tenant_id="tenant-burst",
            subject_id="agent-burst",
            tool_name="deploy_service",
        )

    with ThreadPoolExecutor(max_workers=40) as executor:
        decisions = list(executor.map(attempt, range(40)))

    assert decisions.count(True) == 11
    assert decisions.count(False) == 29


def test_redis_rate_limiter_uses_hashed_scope_and_millisecond_ttl() -> None:
    client = AtomicFakeRedis()
    limiter = RedisToolValidationRateLimiter(
        client=client,
        max_requests=3,
        window_seconds=17,
    )

    assert limiter.allow(
        tenant_id="sensitive-tenant",
        subject_id="alice@example.test",
        tool_name="Delete_Repository",
    )

    script, numkeys, arguments = client.calls[0]
    key = cast(str, arguments[0])
    assert script == REDIS_FIXED_WINDOW_SCRIPT
    assert numkeys == 1
    assert arguments[1:] == (3, 17_000)
    assert key.startswith(RATE_LIMIT_KEY_PREFIX)
    assert re.fullmatch(r"[0-9a-f]{64}", key.removeprefix(RATE_LIMIT_KEY_PREFIX))
    assert "sensitive-tenant" not in key
    assert "alice" not in key
    assert "delete" not in key


def test_redis_rate_limiter_expires_shared_window() -> None:
    now_ms = 100_000
    state = SharedRedisState()
    client = AtomicFakeRedis(state, clock_ms=lambda: now_ms)
    limiter = RedisToolValidationRateLimiter(
        client=client,
        max_requests=1,
        window_seconds=10,
    )
    scope = {"tenant_id": "tenant-a", "subject_id": "agent-a", "tool_name": "lookup"}

    assert limiter.allow(**scope) is True
    assert limiter.allow(**scope) is False
    now_ms = 110_001
    assert limiter.allow(**scope) is True


def test_redis_rate_limiter_maps_outage_and_invalid_protocol_to_typed_errors() -> None:
    unavailable = RedisToolValidationRateLimiter(
        client=OutageRedis(),
        max_requests=1,
        window_seconds=10,
    )
    malformed = RedisToolValidationRateLimiter(
        client=MalformedRedis(),
        max_requests=1,
        window_seconds=10,
    )
    scope = {"tenant_id": "tenant-a", "subject_id": "agent-a", "tool_name": "lookup"}

    with pytest.raises(RateLimitUnavailableError) as unavailable_error:
        unavailable.allow(**scope)
    assert "redis-password-must-not-leak" not in str(unavailable_error.value)
    assert unavailable_error.value.__cause__ is None
    with pytest.raises(RateLimitProtocolError):
        malformed.allow(**scope)
    with pytest.raises(RateLimitUnavailableError) as health_error:
        unavailable.health_check()
    assert health_error.value.__cause__ is None
    with pytest.raises(RateLimitProtocolError):
        malformed.health_check()


def test_factory_resolves_production_rediss_url_from_secret_and_passes_tls_ca(
    tmp_path: Path,
) -> None:
    ca_path = tmp_path / "redis-ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    redis_url = "rediss://:strong-password@redis.internal:6379/0"
    manager = StaticSecretManager({"quotas/custom/url": redis_url})
    factory = RecordingClientFactory(AtomicFakeRedis())
    settings = _settings(
        environment="production",
        secrets_backend="vault",
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_url_secret_name="quotas/custom/url",
        tool_validation_rate_limit_redis_timeout_seconds=0.25,
        tool_validation_rate_limit_redis_ca_path=ca_path,
    )

    limiter = create_tool_validation_rate_limiter(
        settings,
        manager,
        redis_client_factory=factory,
    )

    assert isinstance(limiter, RedisToolValidationRateLimiter)
    assert manager.requested == ["quotas/custom/url"]
    assert factory.calls == [(redis_url, 0.25, ca_path)]


def test_default_redis_client_enforces_ca_verification_and_short_timeouts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca_path = tmp_path / "redis-ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    redis_url = "rediss://:strong-password@redis.internal:6379/0"
    calls: list[tuple[str, dict[str, object]]] = []
    client = AtomicFakeRedis()

    def from_url(url: str, **options: object) -> AtomicFakeRedis:
        calls.append((url, options))
        return client

    monkeypatch.setattr(rate_limit_module.Redis, "from_url", from_url)
    settings = _settings(
        environment="production",
        secrets_backend="vault",
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_timeout_seconds=0.4,
        tool_validation_rate_limit_redis_ca_path=ca_path,
    )

    limiter = create_tool_validation_rate_limiter(
        settings,
        StaticSecretManager({"quotas/tool-validation/redis-url": redis_url}),
    )

    assert isinstance(limiter, RedisToolValidationRateLimiter)
    assert calls == [
        (
            redis_url,
            {
                "socket_connect_timeout": 0.4,
                "socket_timeout": 0.4,
                "retry_on_timeout": False,
                "decode_responses": False,
                "ssl_cert_reqs": ssl.CERT_REQUIRED,
                "ssl_ca_certs": str(ca_path),
            },
        )
    ]


def test_factory_revalidates_directly_constructed_production_settings() -> None:
    direct_url = "rediss://:password@redis.internal:6379/0"
    settings = _settings(
        environment="production",
        secrets_backend="vault",
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_url=direct_url,
        tool_validation_rate_limit_redis_ca_path=None,
    )

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        create_tool_validation_rate_limiter(settings, StaticSecretManager({}))

    assert direct_url not in str(exc_info.value)
    assert "must not configure" in str(exc_info.value)
    assert "REDIS_CA_PATH" in str(exc_info.value)


@pytest.mark.parametrize(
    "redis_url",
    [
        "redis://localhost:0/0",
        "redis://localhost:65536/0",
        "redis://localhost:not-a-port/0",
        "redis://localhost:6379/",
        "redis://localhost:6379/01",
        "redis://localhost:6379/0/extra",
    ],
)
def test_factory_rejects_invalid_port_or_noncanonical_database_path(redis_url: str) -> None:
    settings = _settings(
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_url=redis_url,
    )

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        create_tool_validation_rate_limiter(settings, StaticSecretManager({}))

    assert redis_url not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_factory_redacts_client_construction_errors() -> None:
    redis_url = "redis://:local-password@localhost:6379/0"
    settings = _settings(
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_url=redis_url,
    )

    def fail_factory(url: str, timeout: float, ca_path: Path | None) -> RedisRateLimitClient:
        del timeout, ca_path
        raise ValueError(url)

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        create_tool_validation_rate_limiter(
            settings,
            StaticSecretManager({}),
            redis_client_factory=fail_factory,
        )

    assert redis_url not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert redis_url not in repr(settings)


def test_factory_redacts_secret_backend_failure_without_cause() -> None:
    settings = _settings(tool_validation_rate_limit_backend="redis")

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        create_tool_validation_rate_limiter(settings, StaticSecretManager({}))

    assert exc_info.value.__cause__ is None
    assert "secret-value-must-not-leak" not in str(exc_info.value)


@pytest.mark.parametrize(
    "redis_url",
    [
        "redis://redis.internal:6379/0",
        "https://redis.internal/0",
        "rediss://redis.internal:6379/0?ssl_cert_reqs=none",
    ],
)
def test_factory_rejects_unsafe_production_redis_url_without_leaking_it(
    tmp_path: Path,
    redis_url: str,
) -> None:
    ca_path = tmp_path / "redis-ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    manager = StaticSecretManager({"quotas/tool-validation/redis-url": redis_url})
    settings = _settings(
        environment="production",
        secrets_backend="vault",
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_ca_path=ca_path,
    )

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        create_tool_validation_rate_limiter(settings, manager)

    assert redis_url not in str(exc_info.value)


def test_rate_limit_config_requires_redis_vault_and_ca_in_production(tmp_path: Path) -> None:
    missing = _settings(environment="production")

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        validate_rate_limit_settings(missing)

    message = str(exc_info.value)
    assert "BACKEND=redis" in message
    assert "through Vault" in message
    assert "REDIS_CA_PATH" in message

    ca_path = tmp_path / "redis-ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    validate_rate_limit_settings(
        _settings(
            environment="production",
            secrets_backend="vault",
            tool_validation_rate_limit_backend="redis",
            tool_validation_rate_limit_redis_ca_path=ca_path,
        )
    )


def test_rate_limit_config_restricts_memory_backend_to_local_and_test() -> None:
    with pytest.raises(RateLimitConfigurationError, match="allowed only"):
        validate_rate_limit_settings(_settings(environment="development"))


def test_load_settings_parses_local_redis_rate_limit_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca_path = tmp_path / "redis-ca.pem"
    ca_path.write_text("test-ca", encoding="utf-8")
    monkeypatch.setenv("HALLU_DEFENSE_ENV", "local")
    monkeypatch.setenv("HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setenv(
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME",
        "quotas/custom/redis-url",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL",
        "redis://localhost:6379/2",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS",
        "0.35",
    )
    monkeypatch.setenv(
        "HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH",
        str(ca_path),
    )

    settings = load_settings()

    assert settings.tool_validation_rate_limit_backend == "redis"
    assert settings.tool_validation_rate_limit_redis_url_secret_name == "quotas/custom/redis-url"
    assert settings.tool_validation_rate_limit_redis_url == "redis://localhost:6379/2"
    assert settings.tool_validation_rate_limit_redis_timeout_seconds == pytest.approx(0.35)
    assert settings.tool_validation_rate_limit_redis_ca_path == ca_path.resolve()


def test_rate_limit_config_rejects_direct_url_outside_local_and_invalid_timeout() -> None:
    settings = _settings(
        environment="staging",
        secrets_backend="vault",
        tool_validation_rate_limit_backend="redis",
        tool_validation_rate_limit_redis_url="rediss://redis.internal:6379/0",
        tool_validation_rate_limit_redis_timeout_seconds=0,
    )

    with pytest.raises(RateLimitConfigurationError) as exc_info:
        validate_rate_limit_settings(settings)

    message = str(exc_info.value)
    assert "allowed only in local or test" in message
    assert "TIMEOUT_SECONDS must be positive" in message


def test_rate_limit_metrics_expose_only_bounded_outcome_labels() -> None:
    metrics = PrometheusMetrics(
        service_name="rate-limit-test",
        service_version="test",
        environment="test",
    )

    metrics.record_tool_validation_rate_limit(outcome="allowed")
    metrics.record_tool_validation_rate_limit(outcome="blocked")
    metrics.record_tool_validation_rate_limit(outcome="unavailable")

    rendered = metrics.render()
    assert 'hallu_tool_validation_rate_limit_total{outcome="allowed"} 1' in rendered
    assert 'hallu_tool_validation_rate_limit_total{outcome="blocked"} 1' in rendered
    assert 'hallu_tool_validation_rate_limit_total{outcome="unavailable"} 1' in rendered
    assert "tenant" not in "\n".join(
        line for line in rendered.splitlines() if "tool_validation_rate_limit" in line
    )
    with pytest.raises(ValueError, match="Unsupported"):
        metrics.record_tool_validation_rate_limit(outcome="tenant-a")


def test_tool_validation_endpoint_fails_closed_without_creating_approval(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FailingLimiter:
        def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool:
            del tenant_id, subject_id, tool_name
            raise RateLimitUnavailableError("redis-password-must-not-leak")

        def health_check(self) -> None:
            raise RateLimitUnavailableError("redis-password-must-not-leak")

    class ApprovalMustNotBeCreated:
        def request_approval(self, **kwargs: object) -> object:
            del kwargs
            raise AssertionError("approval must not be created while rate limiting is unavailable")

    metrics = PrometheusMetrics(
        service_name="rate-limit-test",
        service_version="test",
        environment="test",
    )
    monkeypatch.setattr(
        routes,
        "tool_validation_rate_limiter",
        cast(ToolValidationRateLimitBackend, FailingLimiter()),
    )
    monkeypatch.setattr(routes, "approval_queue", ApprovalMustNotBeCreated())
    monkeypatch.setattr(routes, "metrics_collector", metrics)
    caplog.set_level("WARNING", logger="hallu_defense.api.routes")

    response = TestClient(app).post(
        "/tools/validate-input",
        headers={
            "x-tenant-id": "tenant-rate-limit-outage",
            "x-subject-id": "agent-rate-limit-outage",
            "x-trace-id": "tr_rate_limit_outage",
        },
        json={
            "tool_name": "delete_repository",
            "input": {"repo": "core"},
            "schema": {"type": "object"},
            "risk_level": "high",
            "approval_required": False,
            "caller_context": {"subject": "agent-rate-limit-outage"},
        },
    )

    assert response.status_code == 503
    assert response.json()["message"] == "Tool validation rate limit is unavailable."
    assert "redis-password-must-not-leak" not in response.text
    assert "redis-password-must-not-leak" not in caplog.text
    assert (
        'hallu_tool_validation_rate_limit_total{outcome="unavailable"} 1'
        in metrics.render()
    )


@pytest.mark.parametrize(
    ("endpoint", "phase"),
    [
        ("/tools/validate-input", "input"),
        ("/tools/validate-output", "output"),
    ],
)
def test_tool_rate_limit_runs_before_policy_or_content_scanning(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    phase: str,
) -> None:
    class DenyingLimiter:
        def __init__(self) -> None:
            self.tool_names: list[str] = []

        def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool:
            assert tenant_id == "tenant-rate-first"
            assert subject_id == "agent-rate-first"
            self.tool_names.append(tool_name)
            return False

        def health_check(self) -> None:
            return None

    class SafetyMustNotRun:
        def validate_input(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("input policy must not run after a quota rejection")

        def validate_output(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("output scanning must not run after a quota rejection")

    limiter = DenyingLimiter()
    monkeypatch.setattr(
        routes,
        "tool_validation_rate_limiter",
        cast(ToolValidationRateLimitBackend, limiter),
    )
    monkeypatch.setattr(routes, "tool_safety", SafetyMustNotRun())

    response = TestClient(app).post(
        endpoint,
        headers={
            "x-tenant-id": "tenant-rate-first",
            "x-subject-id": "agent-rate-first",
            "x-trace-id": "tr_rate_first",
        },
        json={
            "tool_name": "fetch_record",
            "input": {"record_id": "123"},
            "schema": {
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
                "additionalProperties": False,
            },
            "risk_level": "low",
            "approval_required": False,
            "caller_context": {"subject": "agent-rate-first"},
        },
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["action"] == "block"
    assert response.json()["trace_id"] == "tr_rate_first"
    assert limiter.tool_names == [f"fetch_record:{phase}"]
