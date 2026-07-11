from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from threading import Event, Thread

from pydantic import ValidationError

from hallu_defense import __version__
from hallu_defense.config import RUNTIME_ROLE_WORKER, Settings, load_settings
from hallu_defense.domain.models import DocumentIngestionRequest, DocumentInput
from hallu_defense.services import (
    AuditLedger,
    ContentSecurityScanner,
    DocumentIngestionService,
    HybridRetriever,
    PgVectorRagBackfillSource,
    PostgresMigrationsReadinessCheck,
    PrometheusMetrics,
    PsycopgMigrationLedgerReader,
    RagAccessPolicy,
    RagCorpusReindexer,
    create_audit_ledger,
    create_corpus_grant_registry,
    create_rag_index_backend,
    create_secret_manager,
    discover_expected_migrations,
    locate_migrations_dir,
)
from hallu_defense.services.ingestion_jobs import (
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    PostgresIngestionJobQueue,
)
from hallu_defense.services.postgres import SqlConnectionProvider, build_postgres_provider
from hallu_defense.services.rag_index import (
    RagIndexBackend,
    RagIndexTenantDeletedError,
    RagIndexTransportError,
)
from hallu_defense.services.metrics_server import WorkerMetricsServer
from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretConfigurationError,
    SecretNotFoundError,
)
from hallu_defense.services.secret_token import (
    RotatingSecretTokenVerifier,
    validate_bearer_token,
)

LOGGER = logging.getLogger(__name__)


class IngestionWorkerError(RuntimeError):
    pass


class IngestionLeaseHeartbeatError(IngestionWorkerError):
    pass


class IngestionLeaseHeartbeat:
    def __init__(
        self,
        *,
        queue: PostgresIngestionJobQueue,
        job: IngestionJob,
        worker_id: str,
        lease_token: str,
        interval_seconds: float,
    ) -> None:
        self._queue = queue
        self._job = job
        self._worker_id = worker_id
        self._lease_token = lease_token
        self._interval_seconds = interval_seconds
        self._stop_event = Event()
        self._failure: Exception | None = None
        self._thread = Thread(
            target=self._run,
            name=f"ingestion-lease-heartbeat-{job.job_id}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> Exception | None:
        self._stop_event.set()
        self._thread.join()
        return self._failure

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval_seconds):
            try:
                self._queue.heartbeat(
                    job_id=self._job.job_id,
                    tenant_id=self._job.tenant_id,
                    worker_id=self._worker_id,
                    lease_token=self._lease_token,
                )
            except Exception as exc:
                self._failure = exc
                self._stop_event.set()
                return


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
        heartbeat_seconds: float | None = None,
        reindexer: RagCorpusReindexer | None = None,
        preserve_hybrid_write_intents: bool = False,
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
        effective_heartbeat_seconds = (
            heartbeat_seconds if heartbeat_seconds is not None else lock_timeout_seconds / 3
        )
        if effective_heartbeat_seconds <= 0:
            raise IngestionWorkerError("heartbeat_seconds must be positive.")
        if effective_heartbeat_seconds >= lock_timeout_seconds:
            raise IngestionWorkerError("heartbeat_seconds must be less than lock_timeout_seconds.")
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
        self._heartbeat_seconds = effective_heartbeat_seconds
        self._backfill_page_size = backfill_page_size
        self._reindexer = reindexer
        self._preserve_hybrid_write_intents = preserve_hybrid_write_intents
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def render_metrics(self) -> str:
        return self._metrics.render()

    def run_once(self) -> int:
        self._requeue_stale_running_jobs()
        processed = 0
        while processed < self._batch_size:
            jobs = self._queue.claim_batch(worker_id=self._worker_id, batch_size=1)
            if not jobs:
                break
            if len(jobs) != 1:
                raise IngestionWorkerError("Single-job claim returned an invalid batch size.")
            job = jobs[0]
            self._audit_job_event(job, event_type="ingestion_job_claimed", outcome="claimed")
            self._process_job(job)
            processed += 1
        return processed

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
            preserve_for_reconciliation=self._preserve_hybrid_write_intents,
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
        lease_token = self._required_lease_token(job)
        started = time.perf_counter()
        heartbeat = IngestionLeaseHeartbeat(
            queue=self._queue,
            job=job,
            worker_id=self._worker_id,
            lease_token=lease_token,
            interval_seconds=self._heartbeat_seconds,
        )
        processing_error: Exception | None = None
        heartbeat.start()
        try:
            self._execute_claimed_job(job)
        except Exception as exc:
            processing_error = exc
        finally:
            heartbeat_failure = heartbeat.stop()

        if heartbeat_failure is not None and processing_error is None:
            processing_error = IngestionLeaseHeartbeatError(
                "Ingestion lease heartbeat failed; terminal success is forbidden "
                f"({type(heartbeat_failure).__name__})."
            )

        if isinstance(processing_error, RagIndexTenantDeletedError):
            # Tenant deletion removes the claimed job while holding the same
            # lifecycle lock. Do not recreate tenant-scoped queue/audit data or
            # retry work after the durable fence rejects its persistent write.
            LOGGER.info("Discarded in-flight ingestion for a deleted tenant.")
            return

        if processing_error is not None:
            self._fail_job(
                job,
                lease_token,
                processing_error,
                started=started,
                force_reconciliation=(
                    self._preserve_hybrid_write_intents
                    and heartbeat_failure is not None
                ),
            )
            return

        try:
            completed_job = self._queue.complete(
                job_id=job.job_id,
                tenant_id=job.tenant_id,
                worker_id=self._worker_id,
                lease_token=lease_token,
            )
        except Exception as exc:
            self._fail_job(
                job,
                lease_token,
                exc,
                started=started,
                force_reconciliation=self._preserve_hybrid_write_intents,
            )
            return

        latency_ms = (time.perf_counter() - started) * 1000
        self._record_success_telemetry(completed_job, latency_ms=latency_ms)

    def _execute_claimed_job(self, job: IngestionJob) -> None:
        if job.job_type is IngestionJobType.INGEST:
            self._process_ingest_job(job)
        elif job.job_type is IngestionJobType.REINDEX_CORPUS:
            self._process_reindex_job(job)
        else:
            raise IngestionWorkerError(f"Unsupported ingestion job type: {job.job_type.value}")

    def _fail_job(
        self,
        job: IngestionJob,
        lease_token: str,
        error: Exception,
        *,
        started: float,
        force_reconciliation: bool = False,
    ) -> None:
        transition = (
            self._queue.retry_for_reconciliation
            if self._preserve_hybrid_write_intents
            and (force_reconciliation or isinstance(error, RagIndexTransportError))
            else self._queue.fail
        )
        failed_job = transition(
            job_id=job.job_id,
            tenant_id=job.tenant_id,
            worker_id=self._worker_id,
            lease_token=lease_token,
            error=type(error).__name__,
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
            error_type=type(error).__name__,
        )

    def _record_success_telemetry(self, job: IngestionJob, *, latency_ms: float) -> None:
        try:
            self._metrics.record_ingestion_job(
                status=IngestionJobStatus.SUCCEEDED.value,
                latency_ms=latency_ms,
            )
        except Exception:
            LOGGER.exception(
                "Failed to record terminal ingestion metric",
                extra={"job_id": job.job_id},
            )
        try:
            self._audit_job_event(
                job,
                event_type="ingestion_job_succeeded",
                outcome=IngestionJobStatus.SUCCEEDED.value,
                latency_ms=latency_ms,
            )
        except Exception:
            LOGGER.exception(
                "Failed to record terminal ingestion audit event",
                extra={"job_id": job.job_id},
            )

    def _required_lease_token(self, job: IngestionJob) -> str:
        if job.lease_token is None or not job.lease_token.strip():
            raise IngestionWorkerError("Claimed ingestion job is missing its lease token.")
        return job.lease_token

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
    settings = settings or load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)
    sql_provider = build_postgres_provider(settings)
    queue = PostgresIngestionJobQueue(
        connection=sql_provider,
        max_attempts=settings.ingestion_worker_max_attempts,
        backoff_base_seconds=settings.ingestion_worker_backoff_base_seconds,
    )
    content_scanner = ContentSecurityScanner()
    secret_manager = create_secret_manager(settings)
    rag_backend = create_rag_index_backend(settings, secret_manager)
    retriever = HybridRetriever(index_backend=rag_backend, content_scanner=content_scanner)
    ingestor = DocumentIngestionService(
        retriever,
        access_policy=RagAccessPolicy(
            corpus_grant_registry=create_corpus_grant_registry(
                settings,
                postgres_connection=sql_provider,
            )
        ),
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
        heartbeat_seconds=settings.ingestion_worker_heartbeat_seconds,
        backfill_page_size=settings.ingestion_backfill_page_size,
        reindexer=_build_reindexer(settings, sql_provider, rag_backend),
        preserve_hybrid_write_intents=(
            settings.rag_index_backend.strip().lower() == "hybrid"
        ),
    )


def build_worker_metrics_server(
    settings: Settings,
    worker: IngestionWorker,
    *,
    host: str,
    port: int,
) -> WorkerMetricsServer | None:
    secret_name = settings.metrics_bearer_token_secret_name
    if secret_name is None or not secret_name.strip():
        if settings.environment.strip().lower() in {"production", "staging"}:
            raise IngestionWorkerError(
                "Worker metrics require a bearer-token secret in production and staging."
            )
        return None
    secret_manager = create_secret_manager(settings)
    try:
        initial_token = secret_manager.get_secret(secret_name.strip()).reveal()
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
        raise IngestionWorkerError(
            "Worker metrics bearer-token secret is unavailable."
        ) from None
    try:
        validate_bearer_token(initial_token)
    except ValueError:
        raise IngestionWorkerError(
            "Worker metrics bearer-token secret has an invalid format."
        ) from None
    return WorkerMetricsServer(
        host=host,
        port=port,
        render_metrics=worker.render_metrics,
        token_verifier=RotatingSecretTokenVerifier(
            secret_manager,
            secret_name=secret_name,
        ),
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


def check_worker_readiness(settings: Settings | None = None) -> bool:
    """Bound worker readiness by the configured PostgreSQL and RAG timeouts."""

    try:
        settings = settings or load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)
        dsn = settings.postgres_dsn
        if dsn is None or not dsn.strip():
            raise IngestionWorkerError("Worker readiness requires PostgreSQL.")
        migrations = discover_expected_migrations(locate_migrations_dir())
        PostgresMigrationsReadinessCheck(
            PsycopgMigrationLedgerReader(
                dsn=dsn,
                timeout_seconds=settings.postgres_pool_timeout_seconds,
            ),
            expected_migrations=migrations,
        ).run()

        secret_manager = create_secret_manager(settings)
        rag_backend = create_rag_index_backend(settings, secret_manager)
        if settings.rag_index_backend.strip().lower() in {"opensearch", "hybrid"}:
            health_check = getattr(rag_backend, "health_check", None)
            if not callable(health_check):
                raise IngestionWorkerError(
                    "Worker readiness requires an OpenSearch health probe."
                )
            health_check()
    except Exception as exc:
        LOGGER.warning(
            "Worker readiness dependency check failed.",
            extra={"exception_type": type(exc).__name__},
        )
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the hallu-defense ingestion worker.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="Claim and process one batch, then exit.",
    )
    mode.add_argument(
        "--check-ready",
        action="store_true",
        help="Check bounded PostgreSQL and persistent RAG readiness, then exit.",
    )
    parser.add_argument(
        "--metrics-host",
        default="0.0.0.0",
        help="IP literal used by the authenticated worker metrics endpoint.",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=9090,
        help="TCP port used by the authenticated worker metrics endpoint.",
    )
    args = parser.parse_args(tuple(argv or ()))

    if args.check_ready:
        return 0 if check_worker_readiness() else 1
    settings = load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)
    worker = build_worker_from_settings(settings)
    if args.once:
        worker.run_once()
        return 0
    metrics_server = build_worker_metrics_server(
        settings,
        worker,
        host=args.metrics_host,
        port=args.metrics_port,
    )
    if metrics_server is not None:
        metrics_server.start()
    try:
        worker.run_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        if metrics_server is not None:
            metrics_server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
