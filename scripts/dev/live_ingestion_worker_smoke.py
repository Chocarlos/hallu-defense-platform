from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from importlib import import_module
from pathlib import Path
from typing import BinaryIO, Protocol, Self, cast
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hallu_defense.config import Settings, load_settings  # noqa: E402
from hallu_defense.domain.models import (  # noqa: E402
    Authority,
    Claim,
    ClaimType,
    DocumentIngestionRequest,
    DocumentInput,
    RiskLevel,
)
from hallu_defense.services.ingestion_jobs import (  # noqa: E402
    IngestionJob,
    IngestionJobStatus,
    IngestionJobTransitionError,
    IngestionJobType,
    PostgresIngestionJobQueue,
)
from hallu_defense.services.postgres import (  # noqa: E402
    PooledPostgresProvider,
    SqlConnectionProvider,
    build_postgres_provider,
)
from hallu_defense.services.rag_index import create_rag_index_backend  # noqa: E402
from hallu_defense.services.retrieval import HybridRetriever  # noqa: E402
from scripts.dev.apply_postgres_migrations import (  # noqa: E402
    MIGRATIONS_DIR,
    PsycopgMigrationConnection,
    apply_migrations,
)

ENABLED_ENV = "HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED"
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_RUN_ID = re.compile(r"^[a-z0-9]{8,32}$")
SAFE_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]{1,62}$")
SCRATCH_DATABASE_PREFIX = "hallu_ingestion_smoke_"
SMOKE_LOCK_TIMEOUT_SECONDS = 2.0
SMOKE_HEARTBEAT_SECONDS = 0.4
SMOKE_POLL_SECONDS = 0.05
WORKER_START_TIMEOUT_SECONDS = 30.0
WORKER_EXIT_TIMEOUT_SECONDS = 30.0
LEASE_EXPIRY_MARGIN_SECONDS = 8.0
MAX_WORKER_OUTPUT_BYTES = 64 * 1024
WORKER_MODULE_COMMAND = ("-m", "hallu_defense.worker", "--once")
WORKER_ENV_ALLOWLIST = (
    "PATH",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LD_LIBRARY_PATH",
    "LANG",
    "LC_ALL",
)

_WORKER_WAITING_FOR_PGVECTOR_LOCK_SQL = (
    "SELECT EXISTS ("
    "SELECT 1 FROM pg_stat_activity "
    "WHERE datname = current_database() AND pid <> pg_backend_pid() "
    "AND application_name = %s AND state = 'active' "
    "AND wait_event_type = 'Lock' AND wait_event = 'advisory' "
    "AND query LIKE 'SELECT pg_advisory_xact_lock%%'"
    ") AS is_waiting"
)


class LiveIngestionWorkerSmokeError(RuntimeError):
    pass


class _PsycopgCursor(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool | None: ...

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> object: ...

    def fetchone(self) -> Sequence[object] | None: ...


class _PsycopgConnection(Protocol):
    def cursor(self) -> _PsycopgCursor: ...

    def close(self) -> None: ...


class _PsycopgConnect(Protocol):
    def __call__(self, conninfo: str, *, autocommit: bool) -> _PsycopgConnection: ...


class _ChildProcess(Protocol):
    stdout: BinaryIO | None
    stderr: BinaryIO | None

    def poll(self) -> int | None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass(frozen=True)
class ProcessEvidence:
    returncode: int
    stdout_bytes: int
    stderr_bytes: int


@dataclass
class BoundedOutputCapture:
    """Drain a child pipe continuously while retaining at most the hard limit."""

    stream: BinaryIO
    _buffer: bytearray = field(default_factory=bytearray, init=False)
    _overflowed: bool = field(default=False, init=False)
    _read_failed: bool = field(default=False, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _closed: bool = field(default=False, init=False)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._drain,
            name="bounded-ingestion-worker-output",
            daemon=True,
        )
        self._thread.start()

    def finish(self) -> bytes:
        self.start()
        thread = self._thread
        if thread is None:  # pragma: no cover - defensive invariant
            raise LiveIngestionWorkerSmokeError("Worker output capture did not start.")
        thread.join(timeout=5)
        if thread.is_alive():
            raise LiveIngestionWorkerSmokeError("Worker output capture did not terminate.")
        self._close_stream()
        if self._read_failed:
            raise LiveIngestionWorkerSmokeError("Worker output could not be captured safely.")
        if self._overflowed:
            raise LiveIngestionWorkerSmokeError("Worker output exceeded the bounded capture.")
        return bytes(self._buffer)

    def close(self) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        self._close_stream()

    def _drain(self) -> None:
        try:
            while chunk := self.stream.read(8192):
                remaining = MAX_WORKER_OUTPUT_BYTES - len(self._buffer)
                if remaining > 0:
                    self._buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._overflowed = True
        except (OSError, ValueError):
            self._read_failed = True

    def _close_stream(self) -> None:
        if self._closed:
            return
        try:
            self.stream.close()
        except OSError:
            pass
        self._closed = True


@dataclass
class WorkerProcessHandle:
    process: _ChildProcess
    stdout_capture: BoundedOutputCapture
    stderr_capture: BoundedOutputCapture
    label: str
    closed: bool = False

    def start_output_capture(self) -> None:
        self.stdout_capture.start()
        self.stderr_capture.start()

    def collect_output(self) -> tuple[bytes, bytes]:
        return self.stdout_capture.finish(), self.stderr_capture.finish()

    def close(self) -> None:
        if self.closed:
            return
        self.stdout_capture.close()
        self.stderr_capture.close()
        self.closed = True


@dataclass
class ScratchDatabase:
    admin_dsn: str
    database_name: str
    dsn: str
    connect: _PsycopgConnect
    created: bool = False

    def create(self) -> None:
        if not SAFE_DATABASE_NAME.fullmatch(self.database_name):
            raise LiveIngestionWorkerSmokeError("Scratch database name is invalid.")
        connection = self._connect_admin()
        try:
            with connection.cursor() as cursor:
                cursor.execute(f'CREATE DATABASE "{self.database_name}"')
        except Exception:
            raise LiveIngestionWorkerSmokeError(
                "Could not create the isolated ingestion smoke database."
            ) from None
        finally:
            connection.close()
        self.created = True

    def drop(self) -> None:
        # DROP DATABASE IF EXISTS is intentionally attempted even when CREATE
        # raised. PostgreSQL may have committed CREATE before a transport error
        # reached this process, so trusting only an in-memory flag can leak the
        # scratch database on the exact failure path this smoke is meant to test.
        connection = self._connect_admin()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = %s AND pid <> pg_backend_pid()",
                    (self.database_name,),
                )
                cursor.execute(f'DROP DATABASE IF EXISTS "{self.database_name}"')
        except Exception:
            raise LiveIngestionWorkerSmokeError(
                "Could not remove the isolated ingestion smoke database."
            ) from None
        finally:
            connection.close()
        self.created = False

    def exists(self) -> bool:
        connection = self._connect_admin()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s",
                    (self.database_name,),
                )
                return cursor.fetchone() is not None
        except Exception:
            raise LiveIngestionWorkerSmokeError(
                "Could not verify scratch database cleanup."
            ) from None
        finally:
            connection.close()

    def _connect_admin(self) -> _PsycopgConnection:
        try:
            return self.connect(self.admin_dsn, autocommit=True)
        except Exception:
            raise LiveIngestionWorkerSmokeError(
                "Could not connect to PostgreSQL for isolated database management."
            ) from None


class AdvisoryWriteBarrier:
    def __init__(self, *, connection: _PsycopgConnection, lock_key: str) -> None:
        self._connection = connection
        self._lock_key = lock_key
        self._released = False

    @classmethod
    def acquire(
        cls,
        *,
        dsn: str,
        lock_key: str,
        connect: _PsycopgConnect | None = None,
    ) -> AdvisoryWriteBarrier:
        effective_connect = connect or _load_psycopg_connect()
        connection: _PsycopgConnection | None = None
        try:
            connection = effective_connect(dsn, autocommit=True)
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                    (lock_key,),
                )
        except Exception:
            if connection is not None:
                connection.close()
            raise LiveIngestionWorkerSmokeError(
                "Could not acquire the pgvector crash-test write barrier."
            ) from None
        return cls(connection=connection, lock_key=lock_key)

    def release(self) -> None:
        if self._released:
            return
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                    (self._lock_key,),
                )
        except Exception:
            raise LiveIngestionWorkerSmokeError(
                "Could not release the pgvector crash-test write barrier."
            ) from None
        finally:
            self._connection.close()
            self._released = True


def run_from_env(env: Mapping[str, str] | None = None) -> dict[str, object]:
    effective_env = os.environ if env is None else env
    if effective_env.get(ENABLED_ENV, "").strip().lower() != "true":
        return {
            "status": "skipped",
            "reason": f"set {ENABLED_ENV}=true to run the live ingestion worker smoke",
        }

    base_settings = load_settings()
    if base_settings.environment.strip().lower() not in {"local", "test"}:
        raise LiveIngestionWorkerSmokeError(
            "The crash/restart live smoke is restricted to local or test environments."
        )
    admin_dsn = (base_settings.postgres_dsn or "").strip()
    if not admin_dsn:
        raise LiveIngestionWorkerSmokeError("The live smoke requires PostgreSQL.")

    run_id = _new_run_id()
    scratch = _build_scratch_database(admin_dsn=admin_dsn, run_id=run_id)
    provider: PooledPostgresProvider | None = None
    result: dict[str, object] | None = None
    try:
        scratch.create()
        settings = replace(
            base_settings,
            postgres_dsn=scratch.dsn,
            rag_index_backend="pgvector",
            audit_ledger_backend="postgres",
            corpus_grants_backend="postgres",
            ingestion_mode="async",
            ingestion_worker_batch_size=1,
            ingestion_worker_max_attempts=3,
            ingestion_worker_backoff_base_seconds=0.1,
            ingestion_worker_lock_timeout_seconds=SMOKE_LOCK_TIMEOUT_SECONDS,
            ingestion_worker_heartbeat_seconds=SMOKE_HEARTBEAT_SECONDS,
        )
        apply_migrations(
            PsycopgMigrationConnection(dsn=scratch.dsn),
            migrations_dir=MIGRATIONS_DIR,
        )
        provider = build_postgres_provider(settings)
        result = run_live_smoke(
            settings=settings,
            settings_provider=provider,
            run_id=run_id,
            worker_base_env=effective_env,
        )
    finally:
        try:
            if provider is not None:
                provider.close()
        finally:
            scratch.drop()

    if scratch.exists():
        raise LiveIngestionWorkerSmokeError("Scratch database cleanup was not durable.")
    if result is None:
        raise LiveIngestionWorkerSmokeError("Live smoke produced no result.")
    return {**result, "scratch_database_removed": True}


def run_live_smoke(
    *,
    settings: Settings,
    settings_provider: PooledPostgresProvider,
    run_id: str,
    worker_base_env: Mapping[str, str],
) -> dict[str, object]:
    normalized_run_id = _validate_run_id(run_id)
    table_name = _safe_table(settings.pgvector_table_name)
    dsn = (settings.postgres_dsn or "").strip()
    if not dsn:
        raise LiveIngestionWorkerSmokeError("The scratch PostgreSQL DSN is unavailable.")

    tenant_id = f"tenant-live-ingestion-{normalized_run_id}"
    other_tenant_id = f"tenant-live-ingestion-other-{normalized_run_id}"
    corpus_id = f"corpus-live-ingestion-{normalized_run_id}"
    source_ref = f"live-ingestion-worker-{normalized_run_id}"
    trace_id = f"tr_live_ingestion_crash_{normalized_run_id}"
    worker_id = f"crash-recovery-worker-{normalized_run_id}"
    worker_a_app = f"hallu-ingestion-a-{normalized_run_id}"
    worker_b_app = f"hallu-ingestion-b-{normalized_run_id}"
    document_content = f"Crash recovery document {normalized_run_id} is durable."
    queue = PostgresIngestionJobQueue(
        connection=settings_provider,
        max_attempts=settings.ingestion_worker_max_attempts,
        backoff_base_seconds=settings.ingestion_worker_backoff_base_seconds,
    )
    job: IngestionJob | None = None
    barrier: AdvisoryWriteBarrier | None = None
    worker_a: WorkerProcessHandle | None = None
    worker_b: WorkerProcessHandle | None = None
    result: dict[str, object] | None = None
    forbidden_output_markers = (dsn, document_content)

    _cleanup(
        settings_provider,
        table_name=table_name,
        tenant_id=tenant_id,
        trace_id=trace_id,
        run_id=normalized_run_id,
        job_id=None,
    )
    try:
        barrier = AdvisoryWriteBarrier.acquire(
            dsn=dsn,
            lock_key=_pgvector_write_lock_key(
                tenant_id=tenant_id,
                source_ref=source_ref,
                corpus_id=corpus_id,
            ),
        )
        job = queue.enqueue(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            trace_id=trace_id,
            job_type=IngestionJobType.INGEST,
            payload=_ingest_payload(
                run_id=normalized_run_id,
                corpus_id=corpus_id,
                tenant_id=tenant_id,
                source_ref=source_ref,
                content=document_content,
            ),
        )

        worker_a = _start_worker(
            base_env=worker_base_env,
            settings=settings,
            worker_id=worker_id,
            application_name=worker_a_app,
            label="worker-a",
        )
        first_claim = _wait_for_claim(
            queue,
            job_id=job.job_id,
            tenant_id=tenant_id,
            worker_id=worker_id,
            process=worker_a.process,
        )
        old_token = _required_lease_token(first_claim.lease_token)
        _wait_for_write_barrier(
            settings_provider,
            application_name=worker_a_app,
            process=worker_a.process,
        )
        worker_a_evidence = _finish_worker_process(
            worker_a,
            force_kill=True,
            require_success=False,
            forbidden_markers=forbidden_output_markers,
        )

        crashed_job = queue.get(job_id=job.job_id, tenant_id=tenant_id)
        if (
            crashed_job is None
            or crashed_job.status is not IngestionJobStatus.RUNNING
            or crashed_job.locked_at is None
            or crashed_job.lease_token != old_token
        ):
            raise LiveIngestionWorkerSmokeError(
                "Worker A crash did not leave the claimed lease recoverable."
            )
        observed_lease_age = _wait_for_real_lease_expiry(
            settings_provider,
            locked_at=crashed_job.locked_at,
            lease_timeout_seconds=settings.ingestion_worker_lock_timeout_seconds,
        )

        worker_b = _start_worker(
            base_env=worker_base_env,
            settings=settings,
            worker_id=worker_id,
            application_name=worker_b_app,
            label="worker-b",
        )
        second_claim = _wait_for_claim(
            queue,
            job_id=job.job_id,
            tenant_id=tenant_id,
            worker_id=worker_id,
            process=worker_b.process,
            rejected_token=old_token,
        )
        new_token = _required_lease_token(second_claim.lease_token)
        if new_token == old_token or second_claim.attempts != 1:
            raise LiveIngestionWorkerSmokeError(
                "Worker B did not reclaim the expired job with a new fencing token."
            )
        _wait_for_write_barrier(
            settings_provider,
            application_name=worker_b_app,
            process=worker_b.process,
        )
        rejected_transitions = _assert_old_lease_rejected(
            queue,
            job_id=job.job_id,
            tenant_id=tenant_id,
            worker_id=worker_id,
            old_token=old_token,
            new_token=new_token,
        )
        barrier.release()
        barrier = None
        worker_b_evidence = _finish_worker_process(
            worker_b,
            force_kill=False,
            require_success=True,
            forbidden_markers=forbidden_output_markers,
        )

        final_job = queue.get(job_id=job.job_id, tenant_id=tenant_id)
        if (
            final_job is None
            or final_job.status is not IngestionJobStatus.SUCCEEDED
            or final_job.attempts != 1
            or final_job.lease_token is not None
        ):
            raise LiveIngestionWorkerSmokeError(
                "Worker B did not complete the reclaimed job exactly once."
            )
        chunk_count = _chunk_count(
            settings_provider,
            table_name=table_name,
            tenant_id=tenant_id,
            run_id=normalized_run_id,
        )
        if chunk_count != 1:
            raise LiveIngestionWorkerSmokeError(
                "Crash recovery did not leave exactly one final RAG chunk."
            )
        tenant_retrieval, cross_tenant_empty = _retrieve_smoke_document(
            settings=settings,
            tenant_id=tenant_id,
            other_tenant_id=other_tenant_id,
            run_id=normalized_run_id,
            source_ref=source_ref,
        )
        if not tenant_retrieval or not cross_tenant_empty:
            raise LiveIngestionWorkerSmokeError(
                "Recovered RAG evidence did not preserve the tenant boundary."
            )
        terminal_audits, success_audits, audit_event_count = _audit_counts(
            settings_provider,
            tenant_id=tenant_id,
            trace_id=trace_id,
            job_id=job.job_id,
        )
        if terminal_audits != 1 or success_audits != 1:
            raise LiveIngestionWorkerSmokeError(
                "Crash recovery did not produce exactly one terminal success audit."
            )
        if _job_count(
            settings_provider,
            tenant_id=tenant_id,
            trace_id=trace_id,
        ) != 1:
            raise LiveIngestionWorkerSmokeError(
                "Crash recovery created duplicate ingestion jobs."
            )

        result = {
            "status": "passed",
            "run_id": normalized_run_id,
            "job_id": job.job_id,
            "worker_a_exit_nonzero": worker_a_evidence.returncode != 0,
            "worker_b_exit_zero": worker_b_evidence.returncode == 0,
            "lease_token_rotated": True,
            "lease_expiry_observed_seconds": round(observed_lease_age, 3),
            "old_token_rejected_operations": rejected_transitions,
            "terminal_status": IngestionJobStatus.SUCCEEDED.value,
            "attempts": final_job.attempts,
            "chunk_count": chunk_count,
            "tenant_retrieval": tenant_retrieval,
            "cross_tenant_retrieval_empty": cross_tenant_empty,
            "terminal_audit_count": terminal_audits,
            "success_audit_count": success_audits,
            "audit_event_count": audit_event_count,
            "worker_output_bytes": {
                "a": worker_a_evidence.stdout_bytes + worker_a_evidence.stderr_bytes,
                "b": worker_b_evidence.stdout_bytes + worker_b_evidence.stderr_bytes,
            },
        }
    finally:
        _ensure_worker_stopped(worker_a)
        _ensure_worker_stopped(worker_b)
        if barrier is not None:
            barrier.release()
        _cleanup(
            settings_provider,
            table_name=table_name,
            tenant_id=tenant_id,
            trace_id=trace_id,
            run_id=normalized_run_id,
            job_id=job.job_id if job is not None else None,
        )

    if _smoke_footprint_count(
        settings_provider,
        table_name=table_name,
        tenant_id=tenant_id,
        trace_id=trace_id,
        run_id=normalized_run_id,
    ) != 0:
        raise LiveIngestionWorkerSmokeError("Live ingestion smoke cleanup left database rows.")
    if result is None:
        raise LiveIngestionWorkerSmokeError("Crash/restart orchestration produced no result.")
    return {**result, "cleanup_verified": True}


def _ingest_payload(
    *,
    run_id: str,
    corpus_id: str,
    tenant_id: str,
    source_ref: str,
    content: str,
) -> dict[str, object]:
    request = DocumentIngestionRequest(
        corpus_id=corpus_id,
        documents=[
            DocumentInput(
                source_ref=source_ref,
                content=content,
                authority=Authority.INTERNAL,
                metadata={
                    "smoke_kind": "live_ingestion_worker_crash_recovery",
                    "smoke_run_id": run_id,
                    "owner_tenant_id": tenant_id,
                    "corpus_id": corpus_id,
                },
            )
        ],
    )
    return request.model_dump(mode="json")


def _start_worker(
    *,
    base_env: Mapping[str, str],
    settings: Settings,
    worker_id: str,
    application_name: str,
    label: str,
) -> WorkerProcessHandle:
    dsn = (settings.postgres_dsn or "").strip()
    command = (sys.executable, *WORKER_MODULE_COMMAND)
    if not dsn or any(dsn in argument for argument in command):
        raise LiveIngestionWorkerSmokeError("Worker command construction was unsafe.")
    environment = _worker_environment(
        base_env,
        settings=settings,
        worker_id=worker_id,
        application_name=application_name,
    )
    try:
        process = cast(
            _ChildProcess,
            subprocess.Popen(
                command,
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=os.name != "nt",
            ),
        )
    except (OSError, ValueError):
        raise LiveIngestionWorkerSmokeError("Could not start the ingestion worker process.") from None
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait(timeout=5)
        raise LiveIngestionWorkerSmokeError("Worker output pipes were unavailable.")
    handle = WorkerProcessHandle(
        process=process,
        stdout_capture=BoundedOutputCapture(process.stdout),
        stderr_capture=BoundedOutputCapture(process.stderr),
        label=label,
    )
    handle.start_output_capture()
    return handle


def _worker_environment(
    base_env: Mapping[str, str],
    *,
    settings: Settings,
    worker_id: str,
    application_name: str,
) -> dict[str, str]:
    environment = {
        name: value
        for name in WORKER_ENV_ALLOWLIST
        if (value := base_env.get(name)) is not None and value.strip()
    }
    source_path = str(ROOT / "apps" / "api" / "src")
    inherited_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_path
        if not inherited_pythonpath
        else source_path + os.pathsep + inherited_pythonpath
    )
    environment.update(
        {
            "PYTHONUNBUFFERED": "1",
            "PGAPPNAME": application_name,
            "HALLU_DEFENSE_ENV": "local",
            "HALLU_DEFENSE_RUNTIME_ROLE": "worker",
            "HALLU_DEFENSE_POLICY_VERSION": "live-ingestion-crash-recovery",
            "HALLU_DEFENSE_AUTH_REQUIRED": "false",
            "HALLU_DEFENSE_ALLOWED_WORKSPACE": str(ROOT),
            "HALLU_DEFENSE_PROVIDER_BACKEND": "mock",
            "HALLU_DEFENSE_SECRETS_BACKEND": "env",
            "HALLU_DEFENSE_OTEL_ENABLED": "false",
            "HALLU_DEFENSE_POSTGRES_DSN": (settings.postgres_dsn or ""),
            "HALLU_DEFENSE_POSTGRES_POOL_MIN_SIZE": "1",
            "HALLU_DEFENSE_POSTGRES_POOL_MAX_SIZE": "4",
            "HALLU_DEFENSE_POSTGRES_POOL_TIMEOUT_SECONDS": "5",
            "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND": "postgres",
            "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND": "postgres",
            "HALLU_DEFENSE_RAG_INDEX_BACKEND": "pgvector",
            "HALLU_DEFENSE_PGVECTOR_TABLE_NAME": settings.pgvector_table_name,
            "HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION": str(
                settings.rag_embedding_dimension
            ),
            "HALLU_DEFENSE_INGESTION_MODE": "async",
            "HALLU_DEFENSE_INGESTION_WORKER_ID": worker_id,
            "HALLU_DEFENSE_INGESTION_WORKER_POLL_SECONDS": str(SMOKE_POLL_SECONDS),
            "HALLU_DEFENSE_INGESTION_WORKER_BATCH_SIZE": "1",
            "HALLU_DEFENSE_INGESTION_WORKER_MAX_ATTEMPTS": "3",
            "HALLU_DEFENSE_INGESTION_WORKER_BACKOFF_BASE_SECONDS": "0.1",
            "HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS": str(
                settings.ingestion_worker_lock_timeout_seconds
            ),
            "HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS": str(
                settings.ingestion_worker_heartbeat_seconds
            ),
            "HALLU_DEFENSE_INGESTION_BACKFILL_PAGE_SIZE": "10",
        }
    )
    return environment


def _finish_worker_process(
    handle: WorkerProcessHandle,
    *,
    force_kill: bool,
    require_success: bool,
    forbidden_markers: Sequence[str],
) -> ProcessEvidence:
    try:
        if force_kill:
            if handle.process.poll() is not None:
                raise LiveIngestionWorkerSmokeError(
                    f"{handle.label} exited before the deterministic crash."
                )
            handle.process.kill()
        try:
            returncode = handle.process.wait(timeout=WORKER_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            handle.process.kill()
            handle.process.wait(timeout=5)
            raise LiveIngestionWorkerSmokeError(
                f"{handle.label} exceeded its bounded exit timeout."
            ) from None
        stdout, stderr = handle.collect_output()
        _assert_capture_redacted(stdout, stderr, forbidden_markers=forbidden_markers)
        if require_success and returncode != 0:
            raise LiveIngestionWorkerSmokeError(f"{handle.label} exited unsuccessfully.")
        if not require_success and returncode == 0:
            raise LiveIngestionWorkerSmokeError(
                f"{handle.label} crash did not produce a non-zero exit."
            )
        return ProcessEvidence(
            returncode=returncode,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
        )
    finally:
        handle.close()


def _ensure_worker_stopped(handle: WorkerProcessHandle | None) -> None:
    if handle is None or handle.closed:
        return
    try:
        if handle.process.poll() is None:
            handle.process.kill()
            handle.process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        handle.close()


def _wait_for_claim(
    queue: PostgresIngestionJobQueue,
    *,
    job_id: str,
    tenant_id: str,
    worker_id: str,
    process: _ChildProcess,
    rejected_token: str | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> IngestionJob:
    deadline = monotonic() + WORKER_START_TIMEOUT_SECONDS
    while monotonic() < deadline:
        if process.poll() is not None:
            raise LiveIngestionWorkerSmokeError("Worker exited before claiming its job.")
        current = queue.get(job_id=job_id, tenant_id=tenant_id)
        if (
            current is not None
            and current.status is IngestionJobStatus.RUNNING
            and current.locked_by == worker_id
            and current.lease_token is not None
            and current.lease_token != rejected_token
        ):
            return current
        sleeper(SMOKE_POLL_SECONDS)
    raise LiveIngestionWorkerSmokeError("Timed out waiting for the real worker lease.")


def _wait_for_write_barrier(
    provider: SqlConnectionProvider,
    *,
    application_name: str,
    process: _ChildProcess,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    deadline = monotonic() + WORKER_START_TIMEOUT_SECONDS
    while monotonic() < deadline:
        if process.poll() is not None:
            raise LiveIngestionWorkerSmokeError(
                "Worker exited before reaching the pgvector write barrier."
            )
        rows = provider.fetch_all(
            _WORKER_WAITING_FOR_PGVECTOR_LOCK_SQL,
            (application_name,),
        )
        if rows and rows[0].get("is_waiting") is True:
            return
        sleeper(SMOKE_POLL_SECONDS)
    raise LiveIngestionWorkerSmokeError(
        "Timed out waiting for the worker at the pgvector write barrier."
    )


def _wait_for_real_lease_expiry(
    provider: SqlConnectionProvider,
    *,
    locked_at: datetime,
    lease_timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> float:
    lease_deadline = locked_at + timedelta(seconds=lease_timeout_seconds)
    timeout_at = monotonic() + lease_timeout_seconds + LEASE_EXPIRY_MARGIN_SECONDS
    while monotonic() < timeout_at:
        rows = provider.fetch_all("SELECT clock_timestamp() AS database_now")
        database_now = rows[0].get("database_now") if rows else None
        if not isinstance(database_now, datetime):
            raise LiveIngestionWorkerSmokeError("PostgreSQL did not return its clock.")
        if database_now >= lease_deadline:
            return (database_now - locked_at).total_seconds()
        sleeper(SMOKE_POLL_SECONDS)
    raise LiveIngestionWorkerSmokeError(
        "The real PostgreSQL ingestion lease did not expire before the timeout."
    )


def _assert_old_lease_rejected(
    queue: PostgresIngestionJobQueue,
    *,
    job_id: str,
    tenant_id: str,
    worker_id: str,
    old_token: str,
    new_token: str,
) -> list[str]:
    operations: tuple[tuple[str, Callable[[], object]], ...] = (
        (
            "heartbeat",
            lambda: queue.heartbeat(
                job_id=job_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                lease_token=old_token,
            ),
        ),
        (
            "complete",
            lambda: queue.complete(
                job_id=job_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                lease_token=old_token,
            ),
        ),
        (
            "fail",
            lambda: queue.fail(
                job_id=job_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                lease_token=old_token,
                error="stale_lease_probe",
            ),
        ),
    )
    rejected: list[str] = []
    for name, operation in operations:
        try:
            operation()
        except IngestionJobTransitionError:
            rejected.append(name)
        else:
            raise LiveIngestionWorkerSmokeError(
                "An old ingestion lease token mutated the reclaimed job."
            )
        current = queue.get(job_id=job_id, tenant_id=tenant_id)
        if (
            current is None
            or current.status is not IngestionJobStatus.RUNNING
            or current.lease_token != new_token
        ):
            raise LiveIngestionWorkerSmokeError(
                "Old-token rejection changed the active Worker B lease."
            )
    return rejected


def _retrieve_smoke_document(
    *,
    settings: Settings,
    tenant_id: str,
    other_tenant_id: str,
    run_id: str,
    source_ref: str,
) -> tuple[bool, bool]:
    backend = create_rag_index_backend(settings)
    retriever = HybridRetriever(index_backend=backend)
    claim = Claim(
        claim_id=f"clm_live_ingestion_worker_{run_id}",
        text=f"Crash recovery document {run_id} is durable.",
        type=ClaimType.DOC_GROUNDED,
        risk_level=RiskLevel.MEDIUM,
    )
    filters = {
        "smoke_kind": "live_ingestion_worker_crash_recovery",
        "smoke_run_id": run_id,
    }
    evidence, _claim_map = retriever.retrieve(
        [claim],
        [],
        max_evidence_per_claim=1,
        tenant_id=tenant_id,
        context_refs=[source_ref],
        metadata_filter=filters,
    )
    cross_tenant_evidence, _cross_tenant_map = retriever.retrieve(
        [claim],
        [],
        max_evidence_per_claim=1,
        tenant_id=other_tenant_id,
        context_refs=[source_ref],
        metadata_filter=filters,
    )
    return bool(evidence), not cross_tenant_evidence


def _chunk_count(
    provider: SqlConnectionProvider,
    *,
    table_name: str,
    tenant_id: str,
    run_id: str,
) -> int:
    rows = provider.fetch_all(
        f"SELECT count(*) AS chunk_count FROM {table_name} "
        "WHERE tenant_id = %s AND metadata @> %s::jsonb",
        (tenant_id, _smoke_metadata_json(run_id)),
    )
    return _integer_count(rows, "chunk_count")


def _job_count(
    provider: SqlConnectionProvider,
    *,
    tenant_id: str,
    trace_id: str,
) -> int:
    rows = provider.fetch_all(
        "SELECT count(*) AS job_count FROM rag_ingestion_jobs "
        "WHERE tenant_id = %s AND trace_id = %s",
        (tenant_id, trace_id),
    )
    return _integer_count(rows, "job_count")


def _audit_counts(
    provider: SqlConnectionProvider,
    *,
    tenant_id: str,
    trace_id: str,
    job_id: str,
) -> tuple[int, int, int]:
    rows = provider.fetch_all(
        "SELECT payload FROM audit_events "
        "WHERE tenant_id = %s AND trace_id = %s ORDER BY created_at, id",
        (tenant_id, trace_id),
    )
    terminal_types = {
        "ingestion_job_succeeded",
        "ingestion_job_failed",
        "ingestion_job_dead",
    }
    terminal_count = 0
    success_count = 0
    for row in rows:
        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                raise LiveIngestionWorkerSmokeError("Audit event payload is invalid.") from None
        if not isinstance(payload, Mapping):
            raise LiveIngestionWorkerSmokeError("Audit event payload is not an object.")
        event_type = payload.get("event_type")
        if event_type not in terminal_types:
            continue
        terminal_count += 1
        if event_type == "ingestion_job_succeeded":
            metadata = payload.get("metadata")
            if not isinstance(metadata, Mapping) or metadata.get("job_id") != job_id:
                raise LiveIngestionWorkerSmokeError(
                    "Terminal ingestion audit did not reference the recovered job."
                )
            success_count += 1
    return terminal_count, success_count, len(rows)


def _cleanup(
    provider: SqlConnectionProvider,
    *,
    table_name: str,
    tenant_id: str,
    trace_id: str,
    run_id: str,
    job_id: str | None,
) -> None:
    provider.execute(
        "DELETE FROM audit_events WHERE tenant_id = %s AND trace_id = %s",
        (tenant_id, trace_id),
    )
    provider.execute(
        "DELETE FROM audit_runs WHERE tenant_id = %s AND trace_id = %s",
        (tenant_id, trace_id),
    )
    if job_id is None:
        provider.execute(
            "DELETE FROM rag_ingestion_jobs WHERE tenant_id = %s AND trace_id = %s",
            (tenant_id, trace_id),
        )
    else:
        provider.execute(
            "DELETE FROM rag_ingestion_jobs "
            "WHERE job_id = %s AND tenant_id = %s AND trace_id = %s",
            (job_id, tenant_id, trace_id),
        )
    provider.execute(
        f"DELETE FROM {table_name} WHERE tenant_id = %s AND metadata @> %s::jsonb",
        (tenant_id, _smoke_metadata_json(run_id)),
    )


def _smoke_footprint_count(
    provider: SqlConnectionProvider,
    *,
    table_name: str,
    tenant_id: str,
    trace_id: str,
    run_id: str,
) -> int:
    statements = (
        (
            "SELECT count(*) AS row_count FROM audit_events "
            "WHERE tenant_id = %s AND trace_id = %s",
            (tenant_id, trace_id),
        ),
        (
            "SELECT count(*) AS row_count FROM audit_runs "
            "WHERE tenant_id = %s AND trace_id = %s",
            (tenant_id, trace_id),
        ),
        (
            "SELECT count(*) AS row_count FROM rag_ingestion_jobs "
            "WHERE tenant_id = %s AND trace_id = %s",
            (tenant_id, trace_id),
        ),
        (
            f"SELECT count(*) AS row_count FROM {table_name} "
            "WHERE tenant_id = %s AND metadata @> %s::jsonb",
            (tenant_id, _smoke_metadata_json(run_id)),
        ),
    )
    return sum(
        _integer_count(provider.fetch_all(statement, parameters), "row_count")
        for statement, parameters in statements
    )


def _pgvector_write_lock_key(*, tenant_id: str, source_ref: str, corpus_id: str) -> str:
    return json.dumps([tenant_id, source_ref, corpus_id], separators=(",", ":"))


def _smoke_metadata_json(run_id: str) -> str:
    return json.dumps(
        {
            "smoke_kind": "live_ingestion_worker_crash_recovery",
            "smoke_run_id": run_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _required_lease_token(value: str | None) -> str:
    if value is None or not value.strip():
        raise LiveIngestionWorkerSmokeError("Claimed ingestion job has no fencing token.")
    return value


def _assert_capture_redacted(
    stdout: bytes,
    stderr: bytes,
    *,
    forbidden_markers: Sequence[str],
) -> None:
    combined = stdout + stderr
    for marker in forbidden_markers:
        if marker and marker.encode("utf-8") in combined:
            raise LiveIngestionWorkerSmokeError("Worker output exposed protected runtime data.")


def _build_scratch_database(*, admin_dsn: str, run_id: str) -> ScratchDatabase:
    database_name = SCRATCH_DATABASE_PREFIX + _validate_run_id(run_id)
    return ScratchDatabase(
        admin_dsn=admin_dsn,
        database_name=database_name,
        dsn=_dsn_for_database(admin_dsn, database_name=database_name),
        connect=_load_psycopg_connect(),
    )


def _dsn_for_database(admin_dsn: str, *, database_name: str) -> str:
    if not SAFE_DATABASE_NAME.fullmatch(database_name):
        raise LiveIngestionWorkerSmokeError("Scratch database name is invalid.")
    try:
        parsed = urlsplit(admin_dsn)
        _ = parsed.port
    except ValueError:
        raise LiveIngestionWorkerSmokeError("PostgreSQL DSN is invalid.") from None
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or parsed.hostname is None
        or parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}
        or not parsed.path.strip("/")
        or parsed.fragment
    ):
        raise LiveIngestionWorkerSmokeError(
            "The live smoke requires a loopback PostgreSQL URL DSN with an admin database."
        )
    return urlunsplit(
        (parsed.scheme, parsed.netloc, f"/{database_name}", parsed.query, "")
    )


def _load_psycopg_connect() -> _PsycopgConnect:
    try:
        module = import_module("psycopg")
    except ImportError:
        raise LiveIngestionWorkerSmokeError(
            "The live ingestion smoke requires psycopg."
        ) from None
    connect = getattr(module, "connect", None)
    if not callable(connect):
        raise LiveIngestionWorkerSmokeError("psycopg.connect is unavailable.")
    return cast(_PsycopgConnect, connect)


def _new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def _validate_run_id(run_id: str) -> str:
    normalized = run_id.strip().lower()
    if SAFE_RUN_ID.fullmatch(normalized) is None:
        raise LiveIngestionWorkerSmokeError("Live ingestion run_id is invalid.")
    return normalized


def _safe_table(table_name: str) -> str:
    if not SAFE_IDENTIFIER.fullmatch(table_name):
        raise LiveIngestionWorkerSmokeError(
            "HALLU_DEFENSE_PGVECTOR_TABLE_NAME must be a safe SQL identifier."
        )
    return table_name


def _integer_count(rows: Sequence[Mapping[str, object]], key: str) -> int:
    value = rows[0].get(key) if rows else 0
    if not isinstance(value, int) or isinstance(value, bool):
        raise LiveIngestionWorkerSmokeError("PostgreSQL returned an invalid count.")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        result = run_from_env()
    except Exception as exc:
        failure: dict[str, object] = {
            "status": "failed",
            "error_type": type(exc).__name__,
        }
        if isinstance(exc, LiveIngestionWorkerSmokeError):
            failure["error"] = str(exc)
        print(
            json.dumps(
                failure,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
