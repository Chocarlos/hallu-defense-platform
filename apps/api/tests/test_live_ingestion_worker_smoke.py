# ruff: noqa: SLF001
from __future__ import annotations

import json
import io
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

import pytest

from hallu_defense.config import Settings
from hallu_defense.services.ingestion_jobs import (
    IngestionJob,
    IngestionJobStatus,
    IngestionJobTransitionError,
    IngestionJobType,
)
from hallu_defense.services.postgres import (
    PooledPostgresProvider,
    RecordingSqlProvider,
)
from scripts.dev import live_ingestion_worker_smoke as smoke

FIXED_NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)
TEST_DSN = "postgresql://smoke:redacted@127.0.0.1:5432/control?sslmode=disable"


def test_live_ingestion_worker_smoke_skips_by_default() -> None:
    result = smoke.run_from_env({})

    assert result["status"] == "skipped"
    assert smoke.ENABLED_ENV in str(result["reason"])


def test_scratch_dsn_changes_only_database_and_rejects_non_url_dsn() -> None:
    scratch_dsn = smoke._dsn_for_database(
        TEST_DSN,
        database_name="hallu_ingestion_smoke_abcdef12",
    )

    assert scratch_dsn == (
        "postgresql://smoke:redacted@127.0.0.1:5432/"
        "hallu_ingestion_smoke_abcdef12?sslmode=disable"
    )
    with pytest.raises(smoke.LiveIngestionWorkerSmokeError) as exc_info:
        smoke._dsn_for_database(
            "host=127.0.0.1 password=guard-value dbname=control",
            database_name="hallu_ingestion_smoke_abcdef12",
        )
    assert "guard-value" not in str(exc_info.value)

    with pytest.raises(smoke.LiveIngestionWorkerSmokeError, match="loopback"):
        smoke._dsn_for_database(
            "postgresql://smoke:redacted@db.example.invalid:5432/control",
            database_name="hallu_ingestion_smoke_abcdef12",
        )


def test_pgvector_barrier_key_matches_writer_compact_json_contract() -> None:
    lock_key = smoke._pgvector_write_lock_key(
        tenant_id="tenant-a",
        source_ref="doc-a",
        corpus_id="corpus-a",
    )

    assert lock_key == '["tenant-a","doc-a","corpus-a"]'
    assert json.loads(lock_key) == ["tenant-a", "doc-a", "corpus-a"]


def test_worker_subprocess_has_fixed_argv_and_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_popen(command: tuple[str, ...], **kwargs: object) -> FakeChildProcess:
        captured["command"] = command
        captured.update(kwargs)
        return FakeChildProcess()

    monkeypatch.setattr(smoke.subprocess, "Popen", fake_popen)
    settings = _settings()
    base_env = {
        "PATH": "test-path",
        "PYTHONPATH": "inherited-pythonpath",
        "DATABASE_URL": TEST_DSN,
        "UNRELATED_RUNTIME_VALUE": "must-not-pass",
    }

    handle = smoke._start_worker(
        base_env=base_env,
        settings=settings,
        worker_id="worker-shared",
        application_name="worker-a-app",
        label="worker-a",
    )
    handle.close()

    command = cast(tuple[str, ...], captured["command"])
    environment = cast(dict[str, str], captured["env"])
    assert command[1:] == smoke.WORKER_MODULE_COMMAND
    assert TEST_DSN not in command
    assert captured["shell"] is False
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["stdout"] is subprocess.PIPE
    assert captured["stderr"] is subprocess.PIPE
    assert environment["HALLU_DEFENSE_POSTGRES_DSN"] == TEST_DSN
    assert environment["HALLU_DEFENSE_INGESTION_WORKER_ID"] == "worker-shared"
    assert environment["PGAPPNAME"] == "worker-a-app"
    assert environment["HALLU_DEFENSE_RAG_INDEX_BACKEND"] == "pgvector"
    assert environment["HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS"] == "2.0"
    assert environment["HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS"] == "0.4"
    assert "DATABASE_URL" not in environment
    assert "UNRELATED_RUNTIME_VALUE" not in environment


def test_wait_for_real_lease_expiry_uses_postgres_clock() -> None:
    provider = SequenceClockProvider(
        [
            FIXED_NOW + timedelta(seconds=1.5),
            FIXED_NOW + timedelta(seconds=2),
        ]
    )
    monotonic = iter((0.0, 0.1, 0.2))
    sleeps: list[float] = []

    observed_age = smoke._wait_for_real_lease_expiry(
        provider,  # type: ignore[arg-type]
        locked_at=FIXED_NOW,
        lease_timeout_seconds=2.0,
        monotonic=lambda: next(monotonic),
        sleeper=sleeps.append,
    )

    assert observed_age == 2.0
    assert provider.statements == [
        "SELECT clock_timestamp() AS database_now",
        "SELECT clock_timestamp() AS database_now",
    ]
    assert sleeps == [smoke.SMOKE_POLL_SECONDS]


def test_wait_for_write_barrier_requires_real_postgres_wait_state() -> None:
    provider = BarrierStateProvider([False, True])
    monotonic = iter((0.0, 0.1, 0.2))
    sleeps: list[float] = []

    smoke._wait_for_write_barrier(
        provider,  # type: ignore[arg-type]
        application_name="worker-a-app",
        process=FakeChildProcess(),
        monotonic=lambda: next(monotonic),
        sleeper=sleeps.append,
    )

    assert len(provider.calls) == 2
    assert all("pg_stat_activity" in statement for statement, _params in provider.calls)
    assert all(params == ("worker-a-app",) for _statement, params in provider.calls)
    assert sleeps == [smoke.SMOKE_POLL_SECONDS]


def test_old_token_cannot_heartbeat_complete_or_fail_same_worker_lease() -> None:
    queue = FenceQueue()

    rejected = smoke._assert_old_lease_rejected(
        queue,  # type: ignore[arg-type]
        job_id=queue.current.job_id,
        tenant_id=queue.current.tenant_id,
        worker_id=cast(str, queue.current.locked_by),
        old_token="lease-old",
        new_token="lease-new",
    )

    assert rejected == ["heartbeat", "complete", "fail"]
    assert queue.rejected_operations == ["heartbeat", "complete", "fail"]
    assert queue.current.status is IngestionJobStatus.RUNNING
    assert queue.current.lease_token == "lease-new"


def test_process_capture_is_bounded_and_errors_never_echo_protected_data() -> None:
    protected = "protected-runtime-marker"
    handle = _worker_handle(
        "worker-a",
        FakeChildProcess(),
        stderr=protected.encode(),
    )

    with pytest.raises(smoke.LiveIngestionWorkerSmokeError) as exc_info:
        smoke._finish_worker_process(
            handle,
            force_kill=True,
            require_success=False,
            forbidden_markers=(protected,),
        )

    assert protected not in str(exc_info.value)
    assert handle.closed is True


def test_process_capture_rejects_output_above_hard_limit() -> None:
    handle = _worker_handle(
        "worker-b",
        FakeChildProcess(returncode=0),
        stdout=b"x" * (smoke.MAX_WORKER_OUTPUT_BYTES + 1),
    )

    with pytest.raises(smoke.LiveIngestionWorkerSmokeError, match="bounded capture"):
        smoke._finish_worker_process(
            handle,
            force_kill=False,
            require_success=True,
            forbidden_markers=(),
        )
    assert handle.closed is True


def test_run_from_env_attempts_scratch_drop_when_migrations_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    scratch = FakeScratchDatabase(events)
    monkeypatch.setattr(smoke, "load_settings", _settings)
    monkeypatch.setattr(smoke, "_build_scratch_database", lambda **_kwargs: scratch)

    def fail_migrations(*_args: object, **_kwargs: object) -> None:
        events.append("migrate")
        raise RuntimeError("migration fixture failed")

    monkeypatch.setattr(smoke, "apply_migrations", fail_migrations)

    with pytest.raises(RuntimeError, match="migration fixture failed"):
        smoke.run_from_env({smoke.ENABLED_ENV: "true"})

    assert events == ["create", "migrate", "drop"]


def test_run_from_env_closes_pool_before_drop_and_verifies_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    scratch = FakeScratchDatabase(events)
    provider = FakeClosableProvider(events)
    monkeypatch.setattr(smoke, "load_settings", _settings)
    monkeypatch.setattr(smoke, "_build_scratch_database", lambda **_kwargs: scratch)
    monkeypatch.setattr(
        smoke,
        "apply_migrations",
        lambda *_args, **_kwargs: events.append("migrate"),
    )
    monkeypatch.setattr(
        smoke,
        "build_postgres_provider",
        lambda _settings: events.append("build") or provider,
    )

    def fake_live_smoke(**kwargs: object) -> dict[str, object]:
        configured = cast(Settings, kwargs["settings"])
        assert configured.postgres_dsn == scratch.dsn
        events.append("smoke")
        return {"status": "passed", "cleanup_verified": True}

    monkeypatch.setattr(smoke, "run_live_smoke", fake_live_smoke)

    result = smoke.run_from_env({smoke.ENABLED_ENV: "true"})

    assert result == {
        "status": "passed",
        "cleanup_verified": True,
        "scratch_database_removed": True,
    }
    assert events == [
        "create",
        "migrate",
        "build",
        "smoke",
        "provider-close",
        "drop",
        "exists",
    ]


def test_scratch_database_drop_targets_only_generated_database() -> None:
    statements: list[tuple[str, tuple[object, ...]]] = []
    connector = RecordingConnect(statements)
    scratch = smoke.ScratchDatabase(
        admin_dsn=TEST_DSN,
        database_name="hallu_ingestion_smoke_abcdef12",
        dsn=TEST_DSN,
        connect=connector,  # type: ignore[arg-type]
    )

    # DROP is safe and idempotent even when CREATE did not return successfully.
    scratch.drop()

    assert statements == [
        (
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            ("hallu_ingestion_smoke_abcdef12",),
        ),
        ('DROP DATABASE IF EXISTS "hallu_ingestion_smoke_abcdef12"', ()),
    ]
    assert connector.conninfos == [(TEST_DSN, True)]


def test_cleanup_statements_are_exactly_scoped() -> None:
    provider = RecordingSqlProvider()

    smoke._cleanup(
        provider,
        table_name="rag_chunks",
        tenant_id="tenant-run",
        trace_id="trace-run",
        run_id="abcdef12",
        job_id="ing-run",
    )

    assert len(provider.calls) == 4
    for operation, statement, _parameters in provider.calls:
        assert operation == "execute"
        assert "DELETE FROM" in statement
        assert " WHERE " in statement
        assert "TRUNCATE" not in statement
    assert provider.calls[2][2] == ("ing-run", "tenant-run", "trace-run")
    assert provider.calls[3][2][0] == "tenant-run"
    assert "abcdef12" in cast(str, provider.calls[3][2][1])


def test_full_offline_orchestration_preserves_crash_restart_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    queue = OfflineOrchestrationQueue(events)
    barrier = OfflineBarrier(events)
    captured_lock_keys: list[str] = []

    def acquire_barrier(**kwargs: object) -> OfflineBarrier:
        captured_lock_keys.append(cast(str, kwargs["lock_key"]))
        events.append("barrier-acquire")
        return barrier

    def start_worker(**kwargs: object) -> smoke.WorkerProcessHandle:
        label = cast(str, kwargs["label"])
        worker_id = cast(str, kwargs["worker_id"])
        events.append(f"start:{label}")
        queue.claim_for(label=label, worker_id=worker_id)
        return _worker_handle(label, FakeChildProcess())

    def wait_for_barrier(
        _provider: object,
        *,
        application_name: str,
        process: object,
    ) -> None:
        del process
        events.append("wait-barrier:a" if "-a-" in application_name else "wait-barrier:b")

    def wait_for_expiry(
        _provider: object,
        *,
        locked_at: datetime,
        lease_timeout_seconds: float,
    ) -> float:
        assert locked_at == FIXED_NOW
        assert lease_timeout_seconds == 2.0
        events.append("lease-expired")
        return 2.0

    def finish_worker(
        handle: smoke.WorkerProcessHandle,
        *,
        force_kill: bool,
        require_success: bool,
        forbidden_markers: object,
    ) -> smoke.ProcessEvidence:
        del forbidden_markers
        events.append(f"finish:{handle.label}")
        handle.close()
        if handle.label == "worker-a":
            assert force_kill is True
            assert require_success is False
            assert queue.current.status is IngestionJobStatus.RUNNING
            return smoke.ProcessEvidence(returncode=-9, stdout_bytes=0, stderr_bytes=0)
        assert barrier.released is True
        assert force_kill is False
        assert require_success is True
        queue.succeed()
        return smoke.ProcessEvidence(returncode=0, stdout_bytes=0, stderr_bytes=0)

    monkeypatch.setattr(smoke, "PostgresIngestionJobQueue", lambda **_kwargs: queue)
    monkeypatch.setattr(
        smoke.AdvisoryWriteBarrier,
        "acquire",
        staticmethod(acquire_barrier),
    )
    monkeypatch.setattr(smoke, "_start_worker", start_worker)
    monkeypatch.setattr(smoke, "_wait_for_write_barrier", wait_for_barrier)
    monkeypatch.setattr(smoke, "_wait_for_real_lease_expiry", wait_for_expiry)
    monkeypatch.setattr(smoke, "_finish_worker_process", finish_worker)
    monkeypatch.setattr(smoke, "_chunk_count", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        smoke,
        "_retrieve_smoke_document",
        lambda **_kwargs: (True, True),
    )
    monkeypatch.setattr(smoke, "_audit_counts", lambda *_args, **_kwargs: (1, 1, 3))
    monkeypatch.setattr(smoke, "_job_count", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        smoke,
        "_cleanup",
        lambda *_args, **_kwargs: events.append("cleanup"),
    )
    monkeypatch.setattr(smoke, "_smoke_footprint_count", lambda *_args, **_kwargs: 0)

    result = smoke.run_live_smoke(
        settings=_settings(),
        settings_provider=cast(PooledPostgresProvider, object()),
        run_id="abcdef12",
        worker_base_env={},
    )

    assert result["status"] == "passed"
    assert result["worker_a_exit_nonzero"] is True
    assert result["worker_b_exit_zero"] is True
    assert result["old_token_rejected_operations"] == ["heartbeat", "complete", "fail"]
    assert result["cleanup_verified"] is True
    assert captured_lock_keys == [
        '["tenant-live-ingestion-abcdef12",'
        '"live-ingestion-worker-abcdef12",'
        '"corpus-live-ingestion-abcdef12"]'
    ]
    assert events.index("lease-expired") < events.index("start:worker-b")
    assert events.index("old:heartbeat") < events.index("barrier-release")
    assert events.index("old:complete") < events.index("barrier-release")
    assert events.index("old:fail") < events.index("barrier-release")
    assert events.index("barrier-release") < events.index("finish:worker-b")
    assert events.count("cleanup") == 2


def test_cli_failure_output_contains_only_error_type(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    protected = "postgresql://protected-runtime-value"

    def fail() -> dict[str, object]:
        raise RuntimeError(protected)

    monkeypatch.setattr(smoke, "run_from_env", fail)

    assert smoke.main([]) == 1
    output = capsys.readouterr().out
    assert protected not in output
    assert json.loads(output) == {"status": "failed", "error_type": "RuntimeError"}


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "local",
        "policy_version": "test",
        "auth_required": False,
        "allowed_workspace": Path(".").resolve(),
        "max_command_seconds": 30,
        "max_output_chars": 12_000,
        "postgres_dsn": TEST_DSN,
        "rag_index_backend": "pgvector",
        "audit_ledger_backend": "postgres",
        "corpus_grants_backend": "postgres",
        "ingestion_mode": "async",
        "ingestion_worker_batch_size": 1,
        "ingestion_worker_max_attempts": 3,
        "ingestion_worker_backoff_base_seconds": 0.1,
        "ingestion_worker_lock_timeout_seconds": 2.0,
        "ingestion_worker_heartbeat_seconds": 0.4,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _job(
    *,
    status: IngestionJobStatus,
    attempts: int = 0,
    locked_by: str | None = None,
    lease_token: str | None = None,
    locked_at: datetime | None = None,
) -> IngestionJob:
    return IngestionJob(
        job_id="ing-offline",
        tenant_id="tenant-live-ingestion-abcdef12",
        corpus_id="corpus-live-ingestion-abcdef12",
        trace_id="tr_live_ingestion_crash_abcdef12",
        job_type=IngestionJobType.INGEST,
        payload={},
        status=status,
        attempts=attempts,
        available_at=FIXED_NOW,
        locked_by=locked_by,
        locked_at=locked_at,
        lease_token=lease_token,
        last_error=None,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
    )


class FakeChildProcess:
    def __init__(self, *, returncode: int | None = None) -> None:
        self.returncode = returncode
        self.killed = False
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def _worker_handle(
    label: str,
    process: FakeChildProcess,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> smoke.WorkerProcessHandle:
    handle = smoke.WorkerProcessHandle(
        process=process,
        stdout_capture=smoke.BoundedOutputCapture(io.BytesIO(stdout)),
        stderr_capture=smoke.BoundedOutputCapture(io.BytesIO(stderr)),
        label=label,
    )
    handle.start_output_capture()
    return handle


class SequenceClockProvider:
    def __init__(self, values: list[datetime]) -> None:
        self.values = list(values)
        self.statements: list[str] = []

    def fetch_all(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> list[dict[str, object]]:
        assert parameters == ()
        self.statements.append(statement)
        return [{"database_now": self.values.pop(0)}]


class BarrierStateProvider:
    def __init__(self, states: list[bool]) -> None:
        self.states = list(states)
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def fetch_all(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> list[dict[str, object]]:
        self.calls.append((statement, parameters))
        return [{"is_waiting": self.states.pop(0)}]


class FenceQueue:
    def __init__(self) -> None:
        self.current = _job(
            status=IngestionJobStatus.RUNNING,
            attempts=1,
            locked_by="shared-worker",
            locked_at=FIXED_NOW,
            lease_token="lease-new",
        )
        self.rejected_operations: list[str] = []

    def get(self, *, job_id: str, tenant_id: str) -> IngestionJob | None:
        assert (job_id, tenant_id) == (self.current.job_id, self.current.tenant_id)
        return self.current

    def heartbeat(self, **kwargs: object) -> IngestionJob:
        return self._reject("heartbeat", kwargs)

    def complete(self, **kwargs: object) -> IngestionJob:
        return self._reject("complete", kwargs)

    def fail(self, **kwargs: object) -> IngestionJob:
        return self._reject("fail", kwargs)

    def _reject(self, operation: str, kwargs: dict[str, object]) -> IngestionJob:
        assert kwargs["worker_id"] == self.current.locked_by
        assert kwargs["lease_token"] == "lease-old"
        self.rejected_operations.append(operation)
        raise IngestionJobTransitionError("stale lease fixture")


class FakeScratchDatabase:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.dsn = TEST_DSN

    def create(self) -> None:
        self.events.append("create")

    def drop(self) -> None:
        self.events.append("drop")

    def exists(self) -> bool:
        self.events.append("exists")
        return False


class FakeClosableProvider:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def close(self) -> None:
        self.events.append("provider-close")


class RecordingCursor:
    def __init__(self, statements: list[tuple[str, tuple[object, ...]]]) -> None:
        self.statements = statements

    def __enter__(self) -> RecordingCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> None:
        self.statements.append((statement, parameters))

    def fetchone(self) -> None:
        return None


class RecordingConnection:
    def __init__(self, statements: list[tuple[str, tuple[object, ...]]]) -> None:
        self._statements = statements

    def cursor(self) -> RecordingCursor:
        return RecordingCursor(self._statements)

    def close(self) -> None:
        return None


class RecordingConnect:
    def __init__(self, statements: list[tuple[str, tuple[object, ...]]]) -> None:
        self._statements = statements
        self.conninfos: list[tuple[str, bool]] = []

    def __call__(self, conninfo: str, *, autocommit: bool) -> RecordingConnection:
        self.conninfos.append((conninfo, autocommit))
        return RecordingConnection(self._statements)


class OfflineBarrier:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.released = False

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        self.events.append("barrier-release")


class OfflineOrchestrationQueue:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.current = _job(status=IngestionJobStatus.QUEUED)

    def enqueue(self, **kwargs: object) -> IngestionJob:
        assert kwargs["tenant_id"] == self.current.tenant_id
        self.events.append("enqueue")
        return self.current

    def claim_for(self, *, label: str, worker_id: str) -> None:
        if label == "worker-a":
            self.current = replace(
                self.current,
                status=IngestionJobStatus.RUNNING,
                attempts=0,
                locked_by=worker_id,
                locked_at=FIXED_NOW,
                lease_token="lease-old",
            )
            return
        self.current = replace(
            self.current,
            status=IngestionJobStatus.RUNNING,
            attempts=1,
            locked_by=worker_id,
            locked_at=FIXED_NOW + timedelta(seconds=3),
            lease_token="lease-new",
        )

    def get(self, *, job_id: str, tenant_id: str) -> IngestionJob | None:
        assert (job_id, tenant_id) == (self.current.job_id, self.current.tenant_id)
        return self.current

    def heartbeat(self, **kwargs: object) -> IngestionJob:
        return self._reject_old("heartbeat", kwargs)

    def complete(self, **kwargs: object) -> IngestionJob:
        return self._reject_old("complete", kwargs)

    def fail(self, **kwargs: object) -> IngestionJob:
        return self._reject_old("fail", kwargs)

    def _reject_old(self, operation: str, kwargs: dict[str, object]) -> IngestionJob:
        assert kwargs["worker_id"] == self.current.locked_by
        assert kwargs["lease_token"] == "lease-old"
        self.events.append(f"old:{operation}")
        raise IngestionJobTransitionError("stale lease fixture")

    def succeed(self) -> None:
        self.current = replace(
            self.current,
            status=IngestionJobStatus.SUCCEEDED,
            locked_by=None,
            locked_at=None,
            lease_token=None,
        )
