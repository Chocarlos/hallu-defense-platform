"""SQL-shape and state-transition tests for the PostgreSQL ingestion outbox.

These tests never touch a database. ``RecordingSqlProvider`` records every
call so assertions can pin the exact statement text and parameter tuple sent
for enqueue/claim/complete/fail, while caller-configured ``returning_rows``
simulate what a real guarded ``UPDATE ... RETURNING`` would return for both
the success and zero-row (guard-rejected) paths.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from hallu_defense.services.ingestion_jobs import (
    DEFAULT_BACKOFF_BASE_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobTransitionError,
    IngestionJobType,
    PostgresIngestionJobQueue,
    _CLAIM_BATCH_SQL,
    _COMPLETE_JOB_SQL,
    _FAIL_JOB_SQL,
    _INSERT_JOB_SQL,
    _REQUEUE_STALE_RUNNING_SQL,
    _SELECT_JOB_SQL,
)
from hallu_defense.services.postgres import RecordingSqlProvider

FIXED_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _queue(
    *,
    provider: RecordingSqlProvider | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS,
) -> tuple[PostgresIngestionJobQueue, RecordingSqlProvider]:
    provider = provider or RecordingSqlProvider()
    queue = PostgresIngestionJobQueue(
        connection=provider,
        clock=lambda: FIXED_NOW,
        max_attempts=max_attempts,
        backoff_base_seconds=backoff_base_seconds,
    )
    return queue, provider


def _row(
    *,
    job_id: str = "ing_abc",
    tenant_id: str = "tenant-a",
    corpus_id: str | None = "corpus-1",
    trace_id: str = "tr_1",
    job_type: str = IngestionJobType.INGEST.value,
    payload: dict[str, object] | None = None,
    status: str = IngestionJobStatus.RUNNING.value,
    attempts: int = 0,
    available_at: datetime = FIXED_NOW,
    locked_by: str | None = "worker-1",
    locked_at: datetime | None = FIXED_NOW,
    last_error: str | None = None,
    created_at: datetime = FIXED_NOW,
    updated_at: datetime = FIXED_NOW,
) -> dict[str, object]:
    return {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "corpus_id": corpus_id,
        "trace_id": trace_id,
        "job_type": job_type,
        "payload": dict(payload or {"document_count": 2}),
        "status": status,
        "attempts": attempts,
        "available_at": available_at,
        "locked_by": locked_by,
        "locked_at": locked_at,
        "last_error": last_error,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def test_enqueue_sends_insert_with_jsonb_payload_and_queued_status() -> None:
    queue, provider = _queue()

    job = queue.enqueue(
        tenant_id="tenant-a",
        corpus_id="corpus-1",
        trace_id="tr_1",
        job_type=IngestionJobType.INGEST,
        payload={"document_count": 2},
    )

    assert job.status is IngestionJobStatus.QUEUED
    assert job.attempts == 0
    assert job.available_at == FIXED_NOW
    expected_payload = json.dumps({"document_count": 2}, sort_keys=True, separators=(",", ":"))
    assert provider.calls == [
        (
            "execute",
            _INSERT_JOB_SQL,
            (
                job.job_id,
                "tenant-a",
                "corpus-1",
                "tr_1",
                "ingest",
                expected_payload,
                "queued",
                0,
                FIXED_NOW,
                FIXED_NOW,
                FIXED_NOW,
            ),
        )
    ]


def test_enqueue_defaults_available_at_to_now_when_not_supplied() -> None:
    queue, _ = _queue()

    job = queue.enqueue(
        tenant_id="tenant-a",
        corpus_id=None,
        trace_id="tr_1",
        job_type=IngestionJobType.REINDEX_CORPUS,
        payload={},
    )

    assert job.available_at == FIXED_NOW
    assert job.job_type is IngestionJobType.REINDEX_CORPUS
    assert job.corpus_id is None


def test_claim_batch_uses_skip_locked_cte_and_parses_returned_rows() -> None:
    provider = RecordingSqlProvider(returning_rows=[_row()])
    queue, _ = _queue(provider=provider)

    claimed = queue.claim_batch(worker_id="worker-1", batch_size=5)

    assert "FOR UPDATE SKIP LOCKED" in _CLAIM_BATCH_SQL
    assert len(claimed) == 1
    job = claimed[0]
    assert isinstance(job, IngestionJob)
    assert job.job_id == "ing_abc"
    assert job.status is IngestionJobStatus.RUNNING
    assert job.locked_by == "worker-1"
    assert provider.calls == [
        (
            "execute_returning",
            _CLAIM_BATCH_SQL,
            (FIXED_NOW, 5, "running", "worker-1", FIXED_NOW, FIXED_NOW),
        )
    ]


def test_claim_batch_returns_empty_list_when_nothing_is_claimable() -> None:
    queue, _ = _queue(provider=RecordingSqlProvider(returning_rows=()))

    claimed = queue.claim_batch(worker_id="worker-1", batch_size=5)

    assert claimed == []


def test_get_uses_tenant_scoped_lookup_and_parses_row() -> None:
    provider = RecordingSqlProvider(fetch_all_rows=[_row(status=IngestionJobStatus.QUEUED.value)])
    queue, _ = _queue(provider=provider)

    job = queue.get(job_id="ing_abc", tenant_id="tenant-a")

    assert job is not None
    assert job.job_id == "ing_abc"
    assert job.tenant_id == "tenant-a"
    assert provider.calls == [
        ("fetch_all", _SELECT_JOB_SQL, ("ing_abc", "tenant-a")),
    ]


def test_get_returns_none_for_missing_tenant_scoped_job() -> None:
    queue, _ = _queue(provider=RecordingSqlProvider(fetch_all_rows=()))

    assert queue.get(job_id="ing_missing", tenant_id="tenant-a") is None


def test_claim_batch_rejects_non_positive_batch_size() -> None:
    queue, _ = _queue()

    with pytest.raises(Exception, match="batch_size"):
        queue.claim_batch(worker_id="worker-1", batch_size=0)


def test_complete_uses_guarded_sql_and_succeeds() -> None:
    provider = RecordingSqlProvider(returning_rows=[{"job_id": "ing_abc"}])
    queue, _ = _queue(provider=provider)

    queue.complete(job_id="ing_abc", tenant_id="tenant-a", worker_id="worker-1")

    assert provider.calls == [
        (
            "execute_returning",
            _COMPLETE_JOB_SQL,
            ("succeeded", FIXED_NOW, "ing_abc", "tenant-a", "running", "worker-1"),
        )
    ]


def test_complete_raises_when_guard_rejects_zero_rows() -> None:
    queue, _ = _queue(provider=RecordingSqlProvider(returning_rows=()))

    with pytest.raises(IngestionJobTransitionError):
        queue.complete(job_id="ing_abc", tenant_id="tenant-a", worker_id="worker-1")


def test_fail_retries_with_exponential_backoff_when_attempts_remain() -> None:
    # attempts=0 going into the guarded UPDATE, max_attempts=5, so
    # attempts + 1 (=1) < 5 -> retry branch: status='failed', available_at
    # pushed out by backoff_base_seconds * 2**0.
    returned_available_at = FIXED_NOW + timedelta(seconds=30)
    provider = RecordingSqlProvider(
        returning_rows=[
            _row(status=IngestionJobStatus.FAILED.value, attempts=1, available_at=returned_available_at)
        ]
    )
    queue, _ = _queue(provider=provider, max_attempts=5, backoff_base_seconds=30.0)

    job = queue.fail(job_id="ing_abc", tenant_id="tenant-a", worker_id="worker-1", error="boom")

    assert job.status is IngestionJobStatus.FAILED
    assert job.attempts == 1
    assert provider.calls == [
        (
            "execute_returning",
            _FAIL_JOB_SQL,
            (
                5,
                "dead",
                "failed",
                5,
                FIXED_NOW,
                30.0,
                "boom",
                FIXED_NOW,
                "ing_abc",
                "tenant-a",
                "running",
                "worker-1",
            ),
        )
    ]


def test_fail_dead_letters_when_max_attempts_reached() -> None:
    provider = RecordingSqlProvider(
        returning_rows=[_row(status=IngestionJobStatus.DEAD.value, attempts=5, locked_by=None, locked_at=None)]
    )
    queue, _ = _queue(provider=provider, max_attempts=5, backoff_base_seconds=30.0)

    job = queue.fail(job_id="ing_abc", tenant_id="tenant-a", worker_id="worker-1", error="boom")

    assert job.status is IngestionJobStatus.DEAD
    assert job.attempts == 5
    assert job.locked_by is None


def test_requeue_stale_running_uses_skip_locked_and_dead_letter_guard() -> None:
    locked_before = FIXED_NOW - timedelta(minutes=5)
    provider = RecordingSqlProvider(
        returning_rows=[_row(status=IngestionJobStatus.FAILED.value, attempts=1, locked_by=None)]
    )
    queue, _ = _queue(provider=provider, max_attempts=5)

    jobs = queue.requeue_stale_running(
        locked_before=locked_before,
        batch_size=2,
    )

    assert "FOR UPDATE SKIP LOCKED" in _REQUEUE_STALE_RUNNING_SQL
    assert "CASE WHEN attempts + 1 >= %s THEN %s ELSE %s END" in _REQUEUE_STALE_RUNNING_SQL
    assert jobs[0].status is IngestionJobStatus.FAILED
    assert provider.calls == [
        (
            "execute_returning",
            _REQUEUE_STALE_RUNNING_SQL,
            (
                "running",
                locked_before,
                2,
                5,
                "dead",
                "failed",
                5,
                FIXED_NOW,
                "worker_lock_expired",
                FIXED_NOW,
            ),
        )
    ]


def test_fail_raises_when_guard_rejects_zero_rows() -> None:
    queue, _ = _queue(provider=RecordingSqlProvider(returning_rows=()))

    with pytest.raises(IngestionJobTransitionError):
        queue.fail(job_id="ing_abc", tenant_id="tenant-a", worker_id="worker-1", error="boom")


def test_job_from_row_parses_string_encoded_jsonb_payload() -> None:
    row = _row(payload={"a": 1})
    row["payload"] = json.dumps({"a": 1})
    provider = RecordingSqlProvider(returning_rows=[row])
    queue, _ = _queue(provider=provider)

    claimed = queue.claim_batch(worker_id="worker-1", batch_size=1)

    assert claimed[0].payload == {"a": 1}


def test_constructor_rejects_invalid_max_attempts_and_backoff() -> None:
    provider = RecordingSqlProvider()
    with pytest.raises(Exception, match="max_attempts"):
        PostgresIngestionJobQueue(connection=provider, max_attempts=0)
    with pytest.raises(Exception, match="backoff_base_seconds"):
        PostgresIngestionJobQueue(connection=provider, backoff_base_seconds=0)
