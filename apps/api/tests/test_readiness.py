from __future__ import annotations

import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Self
from threading import Event, Lock

import pytest
from fastapi.testclient import TestClient

from hallu_defense.api import middleware as api_middleware
from hallu_defense.api.dependencies import get_readiness_service
from hallu_defense.config import AUTH_CLAIMS_MODE_OIDC_JWT, Settings
from hallu_defense.main import app
from hallu_defense.services.oidc import OidcJwtValidationError
from hallu_defense.services.readiness import (
    OidcJwksReadinessCheck,
    EXPECTED_MIGRATION_VERSIONS,
    MigrationFingerprint,
    PostgresMigrationsReadinessCheck,
    ProviderSecretReadinessCheck,
    PsycopgMigrationLedgerReader,
    RagIndexReadinessCheck,
    ReadinessCheckError,
    ReadinessService,
    SCHEMA_MIGRATIONS_QUERY,
    ToolValidationRateLimitReadinessCheck,
    UnavailableReadinessCheck,
    create_readiness_service,
    discover_expected_migrations,
)
from hallu_defense.services.rag_index import (
    OpenSearchRagIndexBackend,
    RagIndexTransportError,
)
from hallu_defense.services.secrets import SecretNotFoundError, SecretValue
from hallu_defense.services.rate_limit import RateLimitUnavailableError
from test_oidc_jwt import _jwks


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "readiness-test",
        "auth_required": False,
        "allowed_workspace": Path.cwd(),
        "max_command_seconds": 5,
        "max_output_chars": 1000,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


class StaticMigrationReader:
    def __init__(self, rows: Sequence[Mapping[str, object]]) -> None:
        self.rows = tuple(rows)
        self.calls = 0

    def fetch_applied_migrations(self) -> Sequence[Mapping[str, object]]:
        self.calls += 1
        return self.rows


def _expected_fingerprints() -> tuple[MigrationFingerprint, ...]:
    return tuple(
        MigrationFingerprint(version, f"{index:064x}")
        for index, version in enumerate(EXPECTED_MIGRATION_VERSIONS, start=1)
    )


def _ledger_rows(
    fingerprints: Sequence[MigrationFingerprint],
) -> list[Mapping[str, object]]:
    return [
        {"version": item.version, "checksum_sha256": item.checksum_sha256}
        for item in fingerprints
    ]


class SecretBearingFailureCheck:
    name = "provider_secret"

    def run(self) -> None:
        raise RuntimeError("provider-secret-value-must-not-leak")


class CountingReadinessCheck:
    name = "counting"

    def __init__(self, *, delay_seconds: float = 0) -> None:
        self.calls = 0
        self.delay_seconds = delay_seconds
        self._lock = Lock()

    def run(self) -> None:
        with self._lock:
            self.calls += 1
        if self.delay_seconds:
            time.sleep(self.delay_seconds)


class BlockingReadinessCheck:
    name = "blocked"

    def __init__(self) -> None:
        self.started = Event()
        self.release = Event()

    def run(self) -> None:
        self.started.set()
        self.release.wait(timeout=1)


class FailingAuditLedger:
    def append_event(self, **kwargs: object) -> None:
        del kwargs
        raise RuntimeError("database-password-must-not-leak")


class StaticSecretManager:
    def __init__(self, values: Mapping[str, str]) -> None:
        self.values = values
        self.requested: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.requested.append(name)
        if field != "value" or name not in self.values:
            raise SecretNotFoundError("provider-secret-value-must-not-leak")
        return SecretValue(name=name, _value=self.values[name])


class StaticOpenSearchHealthTransport:
    def __init__(
        self,
        response: Mapping[str, object] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response or {}
        self.error = error
        self.calls: list[tuple[str, str, float]] = []

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        del body, headers
        self.calls.append((method, path, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.response


class FakeCursor:
    def __init__(self, rows: Sequence[Mapping[str, object]]) -> None:
        self.rows = rows
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> object:
        self.executed.append((statement, tuple(parameters)))
        return None

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        return self.rows


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    def cursor(self) -> FakeCursor:
        return self._cursor


class RecordingConnect:
    def __init__(self, rows: Sequence[Mapping[str, object]]) -> None:
        self.cursor = FakeCursor(rows)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        conninfo: str,
        *,
        connect_timeout: int,
        options: str,
        row_factory: object | None = None,
    ) -> FakeConnection:
        self.calls.append(
            {
                "conninfo": conninfo,
                "connect_timeout": connect_timeout,
                "options": options,
                "row_factory": row_factory,
            }
        )
        return FakeConnection(self.cursor)


def test_readiness_service_reports_internal_failure_without_logging_exception_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="hallu_defense.services.readiness")
    service = ReadinessService([SecretBearingFailureCheck()])

    result = service.check()

    assert result.ready is False
    assert result.failed_checks == ("provider_secret",)
    assert getattr(caplog.records[-1], "readiness_check") == "provider_secret"
    assert "provider-secret-value-must-not-leak" not in caplog.text


def test_readiness_service_single_flights_and_caches_concurrent_probes() -> None:
    check = CountingReadinessCheck(delay_seconds=0.05)
    service = ReadinessService(
        [check],
        cache_ttl_seconds=2,
        total_timeout_seconds=1,
        clock=lambda: 1000.0,
    )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _index: service.check(), range(64)))

    assert all(result.ready for result in results)
    assert check.calls == 1


def test_readiness_service_refreshes_once_after_cache_ttl() -> None:
    now = 1000.0
    check = CountingReadinessCheck()
    service = ReadinessService(
        [check],
        cache_ttl_seconds=2,
        clock=lambda: now,
    )

    assert service.check().ready is True
    now = 1001.0
    assert service.check().ready is True
    now = 1003.0
    assert service.check().ready is True
    assert check.calls == 2


def test_readiness_service_applies_total_timeout_budget() -> None:
    check = BlockingReadinessCheck()
    service = ReadinessService(
        [check],
        cache_ttl_seconds=1,
        total_timeout_seconds=0.02,
    )
    started = time.perf_counter()

    result = service.check()
    elapsed = time.perf_counter() - started
    check.release.set()

    assert result.ready is False
    assert result.failed_checks == ("blocked",)
    assert elapsed < 0.2


def test_readiness_timeout_keeps_one_generation_until_blocked_work_finishes() -> None:
    check = BlockingReadinessCheck()
    service = ReadinessService(
        [check],
        cache_ttl_seconds=0.01,
        total_timeout_seconds=0.02,
    )

    first = service.check()
    time.sleep(0.03)
    repeated = [service.check() for _index in range(5)]

    assert first.ready is False
    assert all(result == first for result in repeated)
    assert service._refreshing is True
    check.release.set()
    deadline = time.monotonic() + 0.5
    while service._refreshing and time.monotonic() < deadline:
        time.sleep(0.005)
    assert service._refreshing is False


def test_postgres_migration_check_requires_exact_versions_and_checksums() -> None:
    expected = _expected_fingerprints()
    complete = StaticMigrationReader(_ledger_rows(expected))
    check = PostgresMigrationsReadinessCheck(
        complete,
        expected_migrations=expected,
    )

    check.run()

    incomplete = PostgresMigrationsReadinessCheck(
        StaticMigrationReader(_ledger_rows(expected[:-1])),
        expected_migrations=expected,
    )
    with pytest.raises(ReadinessCheckError, match="do not match"):
        incomplete.run()


@pytest.mark.parametrize("corruption", ["checksum", "unknown", "missing", "duplicate"])
def test_postgres_migration_check_rejects_ledger_corruption(corruption: str) -> None:
    expected = _expected_fingerprints()
    rows = list(_ledger_rows(expected))
    if corruption == "checksum":
        rows[3] = {**rows[3], "checksum_sha256": "f" * 64}
    elif corruption == "unknown":
        rows.append({"version": "999_unknown.sql", "checksum_sha256": "e" * 64})
    elif corruption == "missing":
        rows[3] = {"version": expected[3].version, "checksum_sha256": None}
    else:
        rows.append(dict(rows[3]))
    check = PostgresMigrationsReadinessCheck(
        StaticMigrationReader(rows),
        expected_migrations=expected,
    )

    with pytest.raises(ReadinessCheckError):
        check.run()


def test_psycopg_readiness_reader_applies_connect_and_statement_timeouts() -> None:
    connect = RecordingConnect(
        [{"version": "000_schema_migrations.sql", "checksum_sha256": "a" * 64}]
    )
    row_factory = object()
    reader = PsycopgMigrationLedgerReader(
        dsn="postgresql://readiness-user@db/readiness",
        timeout_seconds=1.25,
        connect=connect,
        row_factory=row_factory,
    )

    rows = reader.fetch_applied_migrations()

    assert rows == [
        {"version": "000_schema_migrations.sql", "checksum_sha256": "a" * 64}
    ]
    assert connect.calls == [
        {
            "conninfo": "postgresql://readiness-user@db/readiness",
            "connect_timeout": 2,
            "options": "-c statement_timeout=1250",
            "row_factory": row_factory,
        }
    ]
    assert connect.cursor.executed == [(SCHEMA_MIGRATIONS_QUERY, ())]


def test_oidc_readiness_validates_local_jwks_file(tmp_path: Path) -> None:
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps(_jwks()), encoding="utf-8")
    settings = _settings(
        auth_required=True,
        auth_claims_mode=AUTH_CLAIMS_MODE_OIDC_JWT,
        oidc_issuer="https://issuer.example",
        oidc_audience="hallu-defense-api",
        oidc_jwks_path=jwks_path,
    )

    OidcJwksReadinessCheck(settings).run()

    jwks_path.write_text('{"keys":[]}', encoding="utf-8")
    with pytest.raises(ReadinessCheckError) as exc_info:
        OidcJwksReadinessCheck(settings).run()
    assert isinstance(exc_info.value.__cause__, OidcJwtValidationError)


def test_provider_secret_readiness_only_reads_configured_secret() -> None:
    manager = StaticSecretManager({"providers/gateway/api-key": "provider-credential"})
    check = ProviderSecretReadinessCheck(
        manager,
        secret_name="providers/gateway/api-key",
    )

    check.run()

    assert manager.requested == ["providers/gateway/api-key"]


def test_rate_limit_readiness_fails_closed_when_redis_is_unavailable() -> None:
    class FailingRateLimiter:
        def allow(self, *, tenant_id: str, subject_id: str, tool_name: str) -> bool:
            del tenant_id, subject_id, tool_name
            return False

        def health_check(self) -> None:
            raise RateLimitUnavailableError("redis-secret-must-not-leak")

    result = ReadinessService(
        [ToolValidationRateLimitReadinessCheck(FailingRateLimiter())]
    ).check()

    assert result.ready is False
    assert result.failed_checks == ("tool_validation_rate_limit",)


@pytest.mark.parametrize(
    ("response", "transport_error"),
    [
        ({"status": "red", "timed_out": False}, None),
        ({"status": "yellow"}, None),
        (None, RagIndexTransportError("Bearer readiness-secret-marker")),
    ],
)
def test_ready_endpoint_fails_closed_when_opensearch_is_unready_without_leak(
    response: Mapping[str, object] | None,
    transport_error: Exception | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="hallu_defense.services.readiness")
    transport = StaticOpenSearchHealthTransport(response, transport_error)
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=1.25,
        transport=transport,
    )
    app.dependency_overrides[get_readiness_service] = lambda: ReadinessService(
        [RagIndexReadinessCheck(backend)]
    )
    try:
        readiness = TestClient(app).get("/ready")
    finally:
        app.dependency_overrides.pop(get_readiness_service, None)

    assert readiness.status_code == 503
    assert readiness.json()["message"] == "Service dependencies are not ready."
    assert "rag_opensearch" not in readiness.text
    assert "readiness-secret-marker" not in readiness.text
    assert "readiness-secret-marker" not in caplog.text
    assert transport.calls == [("GET", "/_cluster/health", 1.25)]


def test_ready_endpoint_is_ready_when_opensearch_is_yellow() -> None:
    transport = StaticOpenSearchHealthTransport(
        {"status": "yellow", "timed_out": False, "number_of_data_nodes": 1}
    )
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=1.25,
        transport=transport,
    )
    app.dependency_overrides[get_readiness_service] = lambda: ReadinessService(
        [RagIndexReadinessCheck(backend)]
    )
    try:
        readiness = TestClient(app).get("/ready")
    finally:
        app.dependency_overrides.pop(get_readiness_service, None)

    assert readiness.status_code == 200
    assert readiness.json() == {"status": "ready"}


def test_readiness_factory_requires_rag_probe_for_hybrid() -> None:
    result = create_readiness_service(
        _settings(rag_index_backend="hybrid"),
        StaticSecretManager({}),
    ).check()

    assert result.ready is False
    assert result.failed_checks == ("rag_opensearch",)


def test_readiness_factory_runs_configured_hybrid_rag_probe() -> None:
    class HealthyProbe:
        def __init__(self) -> None:
            self.calls = 0

        def health_check(self) -> None:
            self.calls += 1

    probe = HealthyProbe()

    result = create_readiness_service(
        _settings(rag_index_backend="hybrid"),
        StaticSecretManager({}),
        rag_index_backend=probe,
    ).check()

    assert result.ready is True
    assert probe.calls == 1


def test_readiness_factory_requires_redis_rate_limiter_when_configured() -> None:
    settings = _settings(tool_validation_rate_limit_backend="redis")

    result = create_readiness_service(
        settings,
        StaticSecretManager({}),
    ).check()

    assert result.ready is False
    assert result.failed_checks == ("tool_validation_rate_limit",)


def test_readiness_factory_composes_postgres_and_provider_checks(
    tmp_path: Path,
) -> None:
    for index, version in enumerate(EXPECTED_MIGRATION_VERSIONS):
        (tmp_path / version).write_text(f"SELECT {index};\n", encoding="utf-8")
    expected = discover_expected_migrations(tmp_path)
    connect = RecordingConnect(_ledger_rows(expected))
    manager = StaticSecretManager({"providers/gateway/api-key": "credential"})
    settings = _settings(
        postgres_dsn="postgresql://readiness-user@db/readiness",
        postgres_pool_timeout_seconds=2,
        provider_backend="openai-compatible",
        openai_compatible_api_key_secret_name="providers/gateway/api-key",
    )

    result = create_readiness_service(
        settings,
        manager,
        migrations_dir=tmp_path,
        postgres_connect=connect,
    ).check()

    assert result.ready is True
    assert manager.requested == ["providers/gateway/api-key"]
    assert connect.cursor.executed == [(SCHEMA_MIGRATIONS_QUERY, ())]


def test_discover_expected_migrations_requires_bootstrap_file(tmp_path: Path) -> None:
    (tmp_path / "001_rag.sql").write_text("SELECT 1;", encoding="utf-8")

    with pytest.raises(ReadinessCheckError, match="inventory"):
        discover_expected_migrations(tmp_path)


def test_discover_expected_migrations_uses_applier_canonical_newlines(
    tmp_path: Path,
) -> None:
    for version in EXPECTED_MIGRATION_VERSIONS:
        (tmp_path / version).write_bytes(b"SELECT 1;\r\n")

    fingerprints = discover_expected_migrations(tmp_path)

    expected_checksum = hashlib.sha256(b"SELECT 1;\n").hexdigest()
    assert {item.checksum_sha256 for item in fingerprints} == {expected_checksum}


def test_ready_endpoint_is_generic_and_health_remains_live() -> None:
    app.dependency_overrides[get_readiness_service] = lambda: ReadinessService(
        [UnavailableReadinessCheck("postgres")]
    )
    try:
        client = TestClient(app)
        readiness = client.get("/ready", headers={"x-trace-id": "tr_ready_failure"})
        liveness = client.get("/health", headers={"x-trace-id": "tr_health_live"})
    finally:
        app.dependency_overrides.pop(get_readiness_service, None)

    assert readiness.status_code == 503
    assert readiness.json()["message"] == "Service dependencies are not ready."
    assert "postgres" not in readiness.text
    assert liveness.status_code == 200
    assert liveness.json()["status"] == "ok"


def test_ready_endpoint_returns_ready_and_is_documented() -> None:
    app.dependency_overrides[get_readiness_service] = lambda: ReadinessService([])
    try:
        client = TestClient(app)
        response = client.get("/ready")
        openapi = client.get("/openapi.json").json()
    finally:
        app.dependency_overrides.pop(get_readiness_service, None)

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    responses = openapi["paths"]["/ready"]["get"]["responses"]
    assert {"200", "503"}.issubset(responses)
    assert responses["503"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ErrorResponse"
    )


def test_probe_responses_survive_audit_database_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="hallu_defense.api.middleware")
    monkeypatch.setattr(api_middleware, "audit_ledger", FailingAuditLedger())
    app.dependency_overrides[get_readiness_service] = lambda: ReadinessService(
        [UnavailableReadinessCheck("postgres")]
    )
    try:
        client = TestClient(app)
        health = client.get("/health", headers={"x-trace-id": "tr_health_audit_down"})
        ready = client.get("/ready", headers={"x-trace-id": "tr_ready_audit_down"})
    finally:
        app.dependency_overrides.pop(get_readiness_service, None)

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert ready.status_code == 503
    assert ready.json()["message"] == "Service dependencies are not ready."
    audit_records = [
        record for record in caplog.records if record.name == "hallu_defense.api.middleware"
    ]
    assert [getattr(record, "error_type") for record in audit_records] == [
        "RuntimeError",
        "RuntimeError",
    ]
    assert "database-password-must-not-leak" not in caplog.text


def test_business_endpoint_remains_fail_closed_when_audit_database_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api_middleware, "audit_ledger", FailingAuditLedger())
    client = TestClient(app)

    with pytest.raises(RuntimeError, match="database-password-must-not-leak"):
        client.post("/claims/extract", json={})
