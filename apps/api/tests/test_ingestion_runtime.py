from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from hallu_defense import __version__
from hallu_defense import worker as worker_module
from hallu_defense.api import routes
from hallu_defense.config import (
    INGESTION_MODE_ASYNC,
    IngestionConfigurationError,
    Settings,
    validate_ingestion_settings,
)
from hallu_defense.domain.models import (
    Authority,
    DocumentIngestionRequest,
    DocumentInput,
)
from hallu_defense.main import app
from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.ingestion import DocumentIngestionService
from hallu_defense.services.ingestion_jobs import IngestionJob, IngestionJobStatus, IngestionJobType
from hallu_defense.services.metrics import PrometheusMetrics
from hallu_defense.services.rag_index import RagIndexWriteResult
from hallu_defense.services.retrieval import HybridRetriever
from hallu_defense.worker import IngestionWorker

FIXED_NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)


def test_ingestion_settings_default_to_sync() -> None:
    settings = _settings()

    validate_ingestion_settings(settings)

    assert settings.ingestion_mode == "sync"


def test_ingestion_settings_async_requires_postgres_dsn() -> None:
    with pytest.raises(IngestionConfigurationError, match="POSTGRES_DSN"):
        validate_ingestion_settings(_settings(ingestion_mode=INGESTION_MODE_ASYNC, postgres_dsn=None))


def test_worker_cli_help_does_not_build_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        worker_module,
        "build_worker_from_settings",
        lambda: pytest.fail("help output must not build the worker"),
    )

    with pytest.raises(SystemExit) as exc_info:
        worker_module.main(["--help"])

    assert exc_info.value.code == 0


def test_async_ingest_enqueues_prepared_documents_after_writer_role_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = RecordingQueue()
    backend = RecordingRagIndexBackend()
    monkeypatch.setattr(
        routes,
        "get_settings",
        lambda: _settings(ingestion_mode=INGESTION_MODE_ASYNC, postgres_dsn="postgresql://db"),
    )
    monkeypatch.setattr(routes, "ingestion_job_queue", queue)
    monkeypatch.setattr(
        routes,
        "document_ingestor",
        DocumentIngestionService(HybridRetriever(index_backend=backend)),
    )

    response = TestClient(app).post(
        "/documents/ingest",
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_async_ingest",
            "x-subject-id": "writer-1",
            "x-roles": "rag_writer,hr_writer",
        },
        json={
            "corpus_id": "hr",
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Async ingestion validates before enqueue.",
                    "authority": "internal",
                    "metadata": {"corpus_writer_roles": ["hr_writer"]},
                }
            ],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["backend"] == "async"
    assert payload["indexed_count"] == 0
    assert payload["job_id"] == "ing_recorded"
    assert payload["job_status"] == "queued"
    assert backend.indexed_chunks == []
    queued_payload = queue.enqueued[0]["payload"]
    assert isinstance(queued_payload, dict)
    assert queued_payload["corpus_id"] == "hr"
    document_payload = queued_payload["documents"][0]
    assert document_payload["metadata"]["owner_tenant_id"] == "tenant-a"
    assert document_payload["metadata"]["corpus_id"] == "hr"


def test_async_ingest_does_not_enqueue_when_writer_role_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = RecordingQueue()
    monkeypatch.setattr(
        routes,
        "get_settings",
        lambda: _settings(ingestion_mode=INGESTION_MODE_ASYNC, postgres_dsn="postgresql://db"),
    )
    monkeypatch.setattr(routes, "ingestion_job_queue", queue)
    monkeypatch.setattr(routes, "document_ingestor", DocumentIngestionService(HybridRetriever()))

    response = TestClient(app).post(
        "/documents/ingest",
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_async_denied",
            "x-subject-id": "writer-1",
            "x-roles": "rag_writer",
        },
        json={
            "corpus_id": "hr",
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Denied async ingestion must not enqueue.",
                    "authority": "internal",
                    "metadata": {"corpus_writer_roles": ["hr_writer"]},
                }
            ],
        },
    )

    assert response.status_code == 403
    assert queue.enqueued == []


def test_ingestion_status_is_tenant_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    queue = RecordingQueue()
    monkeypatch.setattr(routes, "ingestion_job_queue", queue)

    allowed = TestClient(app).post(
        "/documents/ingest/status",
        headers={"x-tenant-id": "tenant-a", "x-trace-id": "tr_ingestion_status"},
        json={"job_id": "ing_recorded"},
    )
    denied = TestClient(app).post(
        "/documents/ingest/status",
        headers={"x-tenant-id": "tenant-b", "x-trace-id": "tr_ingestion_status_b"},
        json={"job_id": "ing_recorded"},
    )

    assert allowed.status_code == 200
    assert allowed.json()["job_status"] == "queued"
    assert denied.status_code == 404


def test_worker_processes_ingest_job_and_records_audit_and_metrics() -> None:
    job = _job()
    queue = WorkerQueue(claimed=[job])
    audit = AuditLedger()
    metrics = _metrics()
    ingestor = RecordingIngestor()
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=ingestor,  # type: ignore[arg-type]
        audit=audit,
        metrics=metrics,
        worker_id="worker-1",
        batch_size=5,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        backfill_page_size=10,
    )

    assert worker.run_once() == 1

    assert queue.completed == [("ing_abc", "tenant-a", "worker-1")]
    assert ingestor.requests[0].corpus_id == "hr"
    event_types = [event.event_type for event in audit.export_events(tenant_id="tenant-a")]
    assert "ingestion_job_claimed" in event_types
    assert "ingestion_job_succeeded" in event_types
    rendered = metrics.render()
    assert 'hallu_ingestion_jobs_total{status="succeeded"} 1' in rendered
    assert "hallu_ingestion_job_latency_ms" in rendered


def test_worker_failures_retry_or_dead_letter_with_audit() -> None:
    job = _job()
    failed = _job(status=IngestionJobStatus.DEAD, attempts=5)
    queue = WorkerQueue(claimed=[job], failed_job=failed)
    audit = AuditLedger()
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=FailingIngestor(),  # type: ignore[arg-type]
        audit=audit,
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=5,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        backfill_page_size=10,
    )

    worker.run_once()

    assert queue.failed == [("ing_abc", "tenant-a", "worker-1", "RuntimeError")]
    assert [event.event_type for event in audit.export_events(tenant_id="tenant-a")] == [
        "ingestion_job_claimed",
        "ingestion_job_dead",
    ]


def test_worker_processes_reindex_job() -> None:
    job = _job(job_type=IngestionJobType.REINDEX_CORPUS, payload={"corpus_id": "hr", "page_size": 25})
    queue = WorkerQueue(claimed=[job])
    reindexer = RecordingReindexer()
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=RecordingIngestor(),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=5,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        backfill_page_size=10,
        reindexer=reindexer,  # type: ignore[arg-type]
    )

    worker.run_once()

    assert reindexer.calls == [("tenant-a", "hr", 25)]
    assert queue.completed == [("ing_abc", "tenant-a", "worker-1")]


class RecordingQueue:
    def __init__(self) -> None:
        self.enqueued: list[dict[str, object]] = []
        self.job = _job(status=IngestionJobStatus.QUEUED)

    def enqueue(self, **kwargs: object) -> IngestionJob:
        self.enqueued.append(kwargs)
        return self.job

    def get(self, *, job_id: str, tenant_id: str) -> IngestionJob | None:
        if job_id == self.job.job_id and tenant_id == self.job.tenant_id:
            return self.job
        return None


class WorkerQueue:
    def __init__(
        self,
        *,
        claimed: list[IngestionJob],
        failed_job: IngestionJob | None = None,
    ) -> None:
        self._claimed = list(claimed)
        self._failed_job = failed_job
        self.completed: list[tuple[str, str, str]] = []
        self.failed: list[tuple[str, str, str, str]] = []

    def requeue_stale_running(self, **kwargs: object) -> list[IngestionJob]:
        del kwargs
        return []

    def claim_batch(self, *, worker_id: str, batch_size: int) -> list[IngestionJob]:
        del worker_id, batch_size
        claimed = list(self._claimed)
        self._claimed.clear()
        return claimed

    def complete(self, *, job_id: str, tenant_id: str, worker_id: str) -> None:
        self.completed.append((job_id, tenant_id, worker_id))

    def fail(self, *, job_id: str, tenant_id: str, worker_id: str, error: str) -> IngestionJob:
        self.failed.append((job_id, tenant_id, worker_id, error))
        return self._failed_job or _job(status=IngestionJobStatus.FAILED, attempts=1)


class RecordingIngestor:
    def __init__(self) -> None:
        self.requests: list[DocumentIngestionRequest] = []

    def ingest_prepared(
        self,
        documents: list[DocumentInput],
        *,
        corpus_id: str,
        tenant_id: str,
        trace_id: str,
        document_count: int,
    ) -> object:
        del tenant_id, trace_id, document_count
        self.requests.append(DocumentIngestionRequest(corpus_id=corpus_id, documents=documents))
        return object()


class FailingIngestor:
    def ingest_prepared(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("boom")


class RecordingReindexer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []

    def reindex_corpus(self, *, tenant_id: str, corpus_id: str, page_size: int) -> object:
        self.calls.append((tenant_id, corpus_id, page_size))
        return object()


class RecordingRagIndexBackend:
    backend_name = "recording"

    def __init__(self) -> None:
        self.indexed_chunks: list[object] = []

    def index_chunks(self, chunks: Any) -> RagIndexWriteResult:
        self.indexed_chunks.extend(chunks)
        return RagIndexWriteResult(indexed_count=len(chunks), backend=self.backend_name)

    def search(self, search_request: object) -> list[object]:
        del search_request
        return []


def _job(
    *,
    status: IngestionJobStatus = IngestionJobStatus.RUNNING,
    attempts: int = 0,
    job_type: IngestionJobType = IngestionJobType.INGEST,
    payload: Mapping[str, object] | None = None,
) -> IngestionJob:
    return IngestionJob(
        job_id="ing_recorded" if status is IngestionJobStatus.QUEUED else "ing_abc",
        tenant_id="tenant-a",
        corpus_id="hr",
        trace_id="tr_worker",
        job_type=job_type,
        payload=payload
        or {
            "corpus_id": "hr",
            "documents": [
                DocumentInput(
                    source_ref="policy-a",
                    content="Worker ingestion payload.",
                    authority=Authority.INTERNAL,
                    metadata={"owner_tenant_id": "tenant-a", "corpus_id": "hr"},
                ).model_dump(mode="json")
            ],
        },
        status=status,
        attempts=attempts,
        available_at=FIXED_NOW,
        locked_by="worker-1" if status is IngestionJobStatus.RUNNING else None,
        locked_at=FIXED_NOW if status is IngestionJobStatus.RUNNING else None,
        last_error=None,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
    )


def _settings(**overrides: object) -> Settings:
    values = {
        "environment": "local",
        "policy_version": "test",
        "auth_required": False,
        "allowed_workspace": Path(".").resolve(),
        "max_command_seconds": 30,
        "max_output_chars": 12000,
    }
    values.update(overrides)
    return Settings(**values)


def _metrics() -> PrometheusMetrics:
    return PrometheusMetrics(
        service_name="test-worker",
        service_version=__version__,
        environment="test",
    )
