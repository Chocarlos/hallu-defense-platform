"""PostgreSQL ingestion outbox: durable, tenant-scoped async ingestion jobs.

This module owns only the outbox storage/queue primitives -- enqueue, atomic
claim, complete, and fail-with-backoff/dead-letter -- over the
``rag_ingestion_jobs`` table created by
``infra/rag/pgvector/006_ingestion_outbox.sql``. It does not decide when async
mode is used, does not call ``DocumentIngestionService``, and does not expose
an API route; those are separate integration slices that build on this queue.

Claim/complete/fail follow the same "let the database enforce the invariant"
discipline as ``services/approvals.py``: every state transition is a single
``UPDATE ... WHERE ... RETURNING`` statement whose ``WHERE`` clause is the
guard, so concurrent workers can never double-claim a job or race a
transition. ``claim_batch`` additionally uses ``FOR UPDATE SKIP LOCKED`` inside
a CTE so concurrent workers claiming from the same queue skip rows already
locked by another worker's in-flight transaction instead of blocking on them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from uuid import uuid4

from hallu_defense.services.postgres import SqlConnectionProvider

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BACKOFF_BASE_SECONDS = 30.0


class IngestionJobError(Exception):
    """Base error for ingestion outbox operations."""


class IngestionJobTransitionError(IngestionJobError):
    """Raised when a claimed job cannot transition (stale claim, wrong tenant/worker, or already terminal)."""


class IngestionJobType(str, Enum):
    INGEST = "ingest"
    REINDEX_CORPUS = "reindex_corpus"


class IngestionJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD = "dead"


@dataclass(frozen=True)
class IngestionJob:
    job_id: str
    tenant_id: str
    corpus_id: str | None
    trace_id: str
    job_type: IngestionJobType
    payload: Mapping[str, object]
    status: IngestionJobStatus
    attempts: int
    available_at: datetime
    locked_by: str | None
    locked_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime


# --- SQL ----------------------------------------------------------------------
#
# Column order shared by every RETURNING clause below, kept in one constant so
# claim/complete/fail all parse rows through the same helper.
_JOB_COLUMNS = (
    "job_id, tenant_id, corpus_id, trace_id, job_type, payload, status, attempts, "
    "available_at, locked_by, locked_at, last_error, created_at, updated_at"
)

_INSERT_JOB_SQL = (
    "INSERT INTO rag_ingestion_jobs "
    "(job_id, tenant_id, corpus_id, trace_id, job_type, payload, status, attempts, "
    "available_at, created_at, updated_at) "
    "VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)"
)

# The CTE selects candidate rows with FOR UPDATE SKIP LOCKED so a concurrent
# claim from another worker skips locked rows instead of blocking; the outer
# UPDATE then flips only the rows this call actually won the lock on.
_CLAIM_BATCH_SQL = (
    "WITH candidates AS ("
    "SELECT job_id FROM rag_ingestion_jobs "
    "WHERE status IN ('queued', 'failed') AND available_at <= %s "
    "ORDER BY available_at ASC "
    "FOR UPDATE SKIP LOCKED "
    "LIMIT %s"
    ") "
    "UPDATE rag_ingestion_jobs SET status = %s, locked_by = %s, locked_at = %s, updated_at = %s "
    "WHERE job_id IN (SELECT job_id FROM candidates) "
    f"RETURNING {_JOB_COLUMNS}"
)

_COMPLETE_JOB_SQL = (
    "UPDATE rag_ingestion_jobs SET status = %s, locked_by = NULL, locked_at = NULL, updated_at = %s "
    "WHERE job_id = %s AND tenant_id = %s AND status = %s AND locked_by = %s "
    "RETURNING job_id"
)

# attempts + 1 >= max_attempts decides dead-letter vs. retry-with-backoff in a
# single guarded statement; both branches reference the *old* attempts value
# (Postgres evaluates every SET expression against the pre-update row), so no
# read-then-write is needed to compute the outcome.
_FAIL_JOB_SQL = (
    "UPDATE rag_ingestion_jobs SET "
    "attempts = attempts + 1, "
    "status = CASE WHEN attempts + 1 >= %s THEN %s ELSE %s END, "
    "available_at = CASE WHEN attempts + 1 >= %s THEN available_at "
    "ELSE %s + (%s * power(2, attempts)) * interval '1 second' END, "
    "locked_by = NULL, locked_at = NULL, last_error = %s, updated_at = %s "
    "WHERE job_id = %s AND tenant_id = %s AND status = %s AND locked_by = %s "
    f"RETURNING {_JOB_COLUMNS}"
)


class PostgresIngestionJobQueue:
    """Atomic PostgreSQL-backed ingestion outbox queue.

    ``payload`` is stored as ``jsonb`` via ``json.dumps(..., sort_keys=True)``,
    mirroring the redacted-snapshot convention used by the audit ledger and
    approval queue backends. Async ingestion is expected to fail closed without
    PostgreSQL configured; this queue has no in-memory or JSONL fallback.
    """

    def __init__(
        self,
        *,
        connection: SqlConnectionProvider,
        clock: Callable[[], datetime] | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS,
    ) -> None:
        if max_attempts < 1:
            raise IngestionJobError("max_attempts must be at least 1.")
        if backoff_base_seconds <= 0:
            raise IngestionJobError("backoff_base_seconds must be positive.")
        self._connection = connection
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_attempts = max_attempts
        self._backoff_base_seconds = backoff_base_seconds

    def enqueue(
        self,
        *,
        tenant_id: str,
        corpus_id: str | None,
        trace_id: str,
        job_type: IngestionJobType,
        payload: Mapping[str, object],
        available_at: datetime | None = None,
    ) -> IngestionJob:
        now = self._now()
        job = IngestionJob(
            job_id=f"ing_{uuid4().hex}",
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            trace_id=trace_id,
            job_type=job_type,
            payload=dict(payload),
            status=IngestionJobStatus.QUEUED,
            attempts=0,
            available_at=available_at or now,
            locked_by=None,
            locked_at=None,
            last_error=None,
            created_at=now,
            updated_at=now,
        )
        self._connection.execute(
            _INSERT_JOB_SQL,
            (
                job.job_id,
                job.tenant_id,
                job.corpus_id,
                job.trace_id,
                job.job_type.value,
                self._payload(job.payload),
                job.status.value,
                job.attempts,
                job.available_at,
                job.created_at,
                job.updated_at,
            ),
        )
        return job

    def claim_batch(self, *, worker_id: str, batch_size: int) -> list[IngestionJob]:
        if batch_size < 1:
            raise IngestionJobError("batch_size must be at least 1.")
        now = self._now()
        rows = self._connection.execute_returning(
            _CLAIM_BATCH_SQL,
            (
                now,
                batch_size,
                IngestionJobStatus.RUNNING.value,
                worker_id,
                now,
                now,
            ),
        )
        return [self._job_from_row(row) for row in rows]

    def complete(self, *, job_id: str, tenant_id: str, worker_id: str) -> None:
        rows = self._connection.execute_returning(
            _COMPLETE_JOB_SQL,
            (
                IngestionJobStatus.SUCCEEDED.value,
                self._now(),
                job_id,
                tenant_id,
                IngestionJobStatus.RUNNING.value,
                worker_id,
            ),
        )
        if not rows:
            raise IngestionJobTransitionError(
                "Ingestion job is not running under this worker for this tenant."
            )

    def fail(
        self,
        *,
        job_id: str,
        tenant_id: str,
        worker_id: str,
        error: str,
    ) -> IngestionJob:
        now = self._now()
        rows = self._connection.execute_returning(
            _FAIL_JOB_SQL,
            (
                self._max_attempts,
                IngestionJobStatus.DEAD.value,
                IngestionJobStatus.FAILED.value,
                self._max_attempts,
                now,
                self._backoff_base_seconds,
                error,
                now,
                job_id,
                tenant_id,
                IngestionJobStatus.RUNNING.value,
                worker_id,
            ),
        )
        if not rows:
            raise IngestionJobTransitionError(
                "Ingestion job is not running under this worker for this tenant."
            )
        return self._job_from_row(rows[0])

    def _now(self) -> datetime:
        return self._clock()

    def _payload(self, payload: Mapping[str, object]) -> str:
        return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))

    def _job_from_row(self, row: Mapping[str, object]) -> IngestionJob:
        payload = row.get("payload")
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, Mapping):
            raise IngestionJobTransitionError("Ingestion job row payload is not a JSON object.")
        job_type_value = row.get("job_type")
        status_value = row.get("status")
        job_id = row.get("job_id")
        tenant_id = row.get("tenant_id")
        trace_id = row.get("trace_id")
        attempts = row.get("attempts")
        available_at = row.get("available_at")
        created_at = row.get("created_at")
        updated_at = row.get("updated_at")
        if not isinstance(job_id, str) or not isinstance(tenant_id, str) or not isinstance(
            trace_id, str
        ):
            raise IngestionJobTransitionError("Ingestion job row is missing required identifiers.")
        if not isinstance(job_type_value, str) or not isinstance(status_value, str):
            raise IngestionJobTransitionError("Ingestion job row is missing job_type/status.")
        if not isinstance(attempts, int):
            raise IngestionJobTransitionError("Ingestion job row is missing attempts.")
        if not isinstance(available_at, datetime) or not isinstance(created_at, datetime) or not isinstance(
            updated_at, datetime
        ):
            raise IngestionJobTransitionError("Ingestion job row is missing required timestamps.")
        corpus_id = row.get("corpus_id")
        locked_by = row.get("locked_by")
        locked_at = row.get("locked_at")
        last_error = row.get("last_error")
        return IngestionJob(
            job_id=job_id,
            tenant_id=tenant_id,
            corpus_id=corpus_id if isinstance(corpus_id, str) else None,
            trace_id=trace_id,
            job_type=IngestionJobType(job_type_value),
            payload=dict(payload),
            status=IngestionJobStatus(status_value),
            attempts=attempts,
            available_at=available_at,
            locked_by=locked_by if isinstance(locked_by, str) else None,
            locked_at=locked_at if isinstance(locked_at, datetime) else None,
            last_error=last_error if isinstance(last_error, str) else None,
            created_at=created_at,
            updated_at=updated_at,
        )
