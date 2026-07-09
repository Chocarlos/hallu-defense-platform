from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from hallu_defense import __version__
from hallu_defense.config import Settings, load_settings
from hallu_defense.domain.models import DocumentIngestionRequest, DocumentInput
from hallu_defense.services import (
    AuditLedger,
    ContentSecurityScanner,
    DocumentIngestionService,
    HybridRetriever,
    PgVectorRagBackfillSource,
    PrometheusMetrics,
    RagAccessPolicy,
    RagCorpusReindexer,
    create_audit_ledger,
    create_corpus_grant_registry,
    create_rag_index_backend,
)
from hallu_defense.services.ingestion_jobs import (
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    PostgresIngestionJobQueue,
)
from hallu_defense.services.postgres import SqlConnectionProvider, build_postgres_provider
from hallu_defense.services.rag_index import RagIndexBackend


class IngestionWorkerError(RuntimeError):
    pass


class IngestionWorker:
    def __init__(
        self,
        *,
        queue: PostgresIngestionJobQueue,
        ingestor: DocumentIngestionService,
        audit: AuditLedger,
        metrics: PrometheusMetrics,
        worker_id: str,
        batch_size: int,
        poll_seconds: float,
        lock_timeout_seconds: float,
        backfill_page_size: int,
        reindexer: RagCorpusReindexer | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not worker_id.strip():
            raise IngestionWorkerError("worker_id must not be empty.")
        if batch_size <= 0:
            raise IngestionWorkerError("batch_size must be positive.")
        if poll_seconds <= 0:
            raise IngestionWorkerError("poll_seconds must be positive.")
        if lock_timeout_seconds <= 0:
            raise IngestionWorkerError("lock_timeout_seconds must be positive.")
        if backfill_page_size <= 0:
            raise IngestionWorkerError("backfill_page_size must be positive.")
        self._queue = queue
        self._ingestor = ingestor
        self._audit = audit
        self._metrics = metrics
        self._worker_id = worker_id
        self._batch_size = batch_size
        self._poll_seconds = poll_seconds
        self._lock_timeout_seconds = lock_timeout_seconds
        self._backfill_page_size = backfill_page_size
        self._reindexer = reindexer
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def run_once(self) -> int:
        self._requeue_stale_running_jobs()
        jobs = self._queue.claim_batch(worker_id=self._worker_id, batch_size=self._batch_size)
        for job in jobs:
            self._audit_job_event(job, event_type="ingestion_job_claimed", outcome="claimed")
            self._process_job(job)
        return len(jobs)

    def run_forever(self) -> None:
        while True:
            processed = self.run_once()
            if processed == 0:
                time.sleep(self._poll_seconds)

    def _requeue_stale_running_jobs(self) -> None:
        locked_before = self._clock() - timedelta(seconds=self._lock_timeout_seconds)
        jobs = self._queue.requeue_stale_running(
            locked_before=locked_before,
            batch_size=self._batch_size,
        )
        for job in jobs:
            event_type = (
                "ingestion_job_dead"
                if job.status is IngestionJobStatus.DEAD
                else "ingestion_job_requeued"
            )
            self._metrics.record_ingestion_job(status=job.status.value)
            self._audit_job_event(job, event_type=event_type, outcome=job.status.value)

    def _process_job(self, job: IngestionJob) -> None:
        started = time.perf_counter()
        try:
            if job.job_type is IngestionJobType.INGEST:
                self._process_ingest_job(job)
            elif job.job_type is IngestionJobType.REINDEX_CORPUS:
                self._process_reindex_job(job)
            else:
                raise IngestionWorkerError(f"Unsupported ingestion job type: {job.job_type.value}")
            self._queue.complete(
                job_id=job.job_id,
                tenant_id=job.tenant_id,
                worker_id=self._worker_id,
            )
            latency_ms = (time.perf_counter() - started) * 1000
            self._metrics.record_ingestion_job(
                status=IngestionJobStatus.SUCCEEDED.value,
                latency_ms=latency_ms,
            )
            self._audit_job_event(
                job,
                event_type="ingestion_job_succeeded",
                outcome=IngestionJobStatus.SUCCEEDED.value,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            failed_job = self._queue.fail(
                job_id=job.job_id,
                tenant_id=job.tenant_id,
                worker_id=self._worker_id,
                error=type(exc).__name__,
            )
            latency_ms = (time.perf_counter() - started) * 1000
            self._metrics.record_ingestion_job(
                status=failed_job.status.value,
                latency_ms=latency_ms,
            )
            self._audit_job_event(
                failed_job,
                event_type="ingestion_job_dead"
                if failed_job.status is IngestionJobStatus.DEAD
                else "ingestion_job_failed",
                outcome=failed_job.status.value,
                latency_ms=latency_ms,
                error_type=type(exc).__name__,
            )

    def _process_ingest_job(self, job: IngestionJob) -> None:
        try:
            request = DocumentIngestionRequest.model_validate(
                {
                    "corpus_id": job.payload.get("corpus_id") or job.corpus_id or "default",
                    "documents": job.payload.get("documents"),
                }
            )
        except ValidationError as exc:
            raise IngestionWorkerError("Ingestion job payload is not a valid request.") from exc
        documents = [DocumentInput.model_validate(item) for item in request.documents]
        self._ingestor.ingest_prepared(
            documents,
            tenant_id=job.tenant_id,
            trace_id=job.trace_id,
            corpus_id=request.corpus_id,
            document_count=len(request.documents),
        )

    def _process_reindex_job(self, job: IngestionJob) -> None:
        if self._reindexer is None:
            raise IngestionWorkerError("Reindex jobs require a persistent RAG target backend.")
        corpus_id = job.corpus_id or job.payload.get("corpus_id")
        if not isinstance(corpus_id, str) or not corpus_id.strip():
            raise IngestionWorkerError("Reindex job payload must include corpus_id.")
        page_size = _positive_int(job.payload.get("page_size"), default=self._backfill_page_size)
        self._reindexer.reindex_corpus(
            tenant_id=job.tenant_id,
            corpus_id=corpus_id,
            page_size=page_size,
        )

    def _audit_job_event(
        self,
        job: IngestionJob,
        *,
        event_type: str,
        outcome: str,
        latency_ms: float | None = None,
        error_type: str | None = None,
    ) -> None:
        metadata: dict[str, object] = {
            "job_id": job.job_id,
            "job_type": job.job_type.value,
            "job_status": job.status.value,
            "attempts": job.attempts,
            "worker_id": self._worker_id,
        }
        if job.corpus_id is not None:
            metadata["corpus_id"] = job.corpus_id
        if latency_ms is not None:
            metadata["latency_ms"] = round(latency_ms, 3)
        if error_type is not None:
            metadata["error_type"] = error_type
        self._audit.append_event(
            trace_id=job.trace_id,
            tenant_id=job.tenant_id,
            event_type=event_type,
            method="WORKER",
            path="hallu_defense.worker",
            status_code=200 if outcome in {"claimed", "queued", "succeeded"} else 500,
            outcome=outcome,
            metadata=metadata,
        )


def build_worker_from_settings(settings: Settings | None = None) -> IngestionWorker:
    settings = settings or load_settings()
    sql_provider = build_postgres_provider(settings)
    queue = PostgresIngestionJobQueue(
        connection=sql_provider,
        max_attempts=settings.ingestion_worker_max_attempts,
        backoff_base_seconds=settings.ingestion_worker_backoff_base_seconds,
    )
    content_scanner = ContentSecurityScanner()
    rag_backend = create_rag_index_backend(settings)
    retriever = HybridRetriever(index_backend=rag_backend, content_scanner=content_scanner)
    ingestor = DocumentIngestionService(
        retriever,
        access_policy=RagAccessPolicy(corpus_grant_registry=create_corpus_grant_registry(settings)),
    )
    audit = create_audit_ledger(
        settings,
        sql_provider=sql_provider if _uses_postgres(settings.audit_ledger_backend) else None,
    )
    metrics = PrometheusMetrics(
        service_name="hallu-defense-ingestion-worker",
        service_version=__version__,
        environment=settings.environment,
    )
    return IngestionWorker(
        queue=queue,
        ingestor=ingestor,
        audit=audit,
        metrics=metrics,
        worker_id=settings.ingestion_worker_id,
        batch_size=settings.ingestion_worker_batch_size,
        poll_seconds=settings.ingestion_worker_poll_seconds,
        lock_timeout_seconds=settings.ingestion_worker_lock_timeout_seconds,
        backfill_page_size=settings.ingestion_backfill_page_size,
        reindexer=_build_reindexer(settings, sql_provider, rag_backend),
    )


def _build_reindexer(
    settings: Settings,
    sql_provider: SqlConnectionProvider,
    target: RagIndexBackend | None,
) -> RagCorpusReindexer | None:
    if target is None:
        return None
    source = PgVectorRagBackfillSource(
        table_name=settings.pgvector_table_name,
        connection=sql_provider,
    )
    return RagCorpusReindexer(source=source, target=target)


def _uses_postgres(backend: str) -> bool:
    return backend.strip().lower() in {"postgres", "postgresql"}


def _positive_int(value: object, *, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return default


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the hallu-defense ingestion worker.")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Claim and process one batch, then exit.",
    )
    args = parser.parse_args(tuple(argv or ()))

    worker = build_worker_from_settings()
    if args.once:
        worker.run_once()
        return 0
    try:
        worker.run_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
