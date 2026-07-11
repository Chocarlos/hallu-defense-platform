from __future__ import annotations

import os
import time
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
    RUNTIME_ROLE_API,
    RUNTIME_ROLE_WORKER,
    RuntimeRoleConfigurationError,
    Settings,
    load_settings,
    validate_ingestion_settings,
    validate_worker_runtime_settings,
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
from hallu_defense.services.rag_index import (
    RagIndexTenantDeletedError,
    RagIndexTransportError,
    RagIndexWriteResult,
)
from hallu_defense.services.retrieval import HybridRetriever
from hallu_defense.worker import IngestionWorker

FIXED_NOW = datetime(2026, 7, 9, 12, 0, tzinfo=timezone.utc)


def test_ingestion_settings_default_to_sync() -> None:
    settings = _settings()

    validate_ingestion_settings(settings)

    assert settings.ingestion_mode == "sync"
    assert settings.ingestion_worker_heartbeat_seconds < (
        settings.ingestion_worker_lock_timeout_seconds
    )


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_production_like_ingestion_requires_durable_async_journal(
    environment: str,
) -> None:
    with pytest.raises(
        IngestionConfigurationError,
        match="Production and staging require HALLU_DEFENSE_INGESTION_MODE=async",
    ):
        validate_ingestion_settings(_settings(environment=environment, ingestion_mode="sync"))


def test_ingestion_settings_async_requires_postgres_dsn() -> None:
    with pytest.raises(IngestionConfigurationError, match="POSTGRES_DSN"):
        validate_ingestion_settings(
            _settings(ingestion_mode=INGESTION_MODE_ASYNC, postgres_dsn=None)
        )


@pytest.mark.parametrize("heartbeat_seconds", [0, 60])
def test_ingestion_heartbeat_must_be_positive_and_less_than_lock_timeout(
    heartbeat_seconds: float,
) -> None:
    settings = _settings(
        ingestion_worker_lock_timeout_seconds=60,
        ingestion_worker_heartbeat_seconds=heartbeat_seconds,
    )

    with pytest.raises(IngestionConfigurationError, match="HEARTBEAT_SECONDS"):
        validate_ingestion_settings(settings)


def test_load_settings_derives_safe_heartbeat_from_short_lock_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS", "0.3")
    monkeypatch.delenv("HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS", raising=False)

    settings = load_settings()

    assert settings.ingestion_worker_heartbeat_seconds == pytest.approx(0.1)
    assert (
        settings.ingestion_worker_heartbeat_seconds < settings.ingestion_worker_lock_timeout_seconds
    )


def test_worker_cli_help_does_not_build_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        worker_module,
        "build_worker_from_settings",
        lambda: pytest.fail("help output must not build the worker"),
    )

    with pytest.raises(SystemExit) as exc_info:
        worker_module.main(["--help"])

    assert exc_info.value.code == 0


@pytest.mark.parametrize(("ready", "exit_code"), [(True, 0), (False, 1)])
def test_worker_ready_cli_uses_bounded_dependency_check_without_building_worker(
    monkeypatch: pytest.MonkeyPatch,
    ready: bool,
    exit_code: int,
) -> None:
    monkeypatch.setattr(worker_module, "check_worker_readiness", lambda: ready)
    monkeypatch.setattr(
        worker_module,
        "build_worker_from_settings",
        lambda: pytest.fail("readiness must not start the ingestion loop"),
    )

    assert worker_module.main(["--check-ready"]) == exit_code


def test_worker_role_loads_production_hybrid_dependencies_without_api_only_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "HALLU_DEFENSE_AUTH_REQUIRED",
        "HALLU_DEFENSE_AUTH_CLAIMS_MODE",
        "HALLU_DEFENSE_OIDC_ISSUER",
        "HALLU_DEFENSE_OIDC_AUDIENCE",
        "HALLU_DEFENSE_OIDC_JWKS_PATH",
        "HALLU_DEFENSE_CORS_ALLOW_ORIGINS",
        "HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME",
        "HALLU_DEFENSE_PROVIDER_BACKEND",
        "HALLU_DEFENSE_SANDBOX_BACKEND",
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HALLU_DEFENSE_ENV", "production")
    monkeypatch.setenv("HALLU_DEFENSE_RUNTIME_ROLE", RUNTIME_ROLE_WORKER)
    postgres_dsn_file = tmp_path / "postgres-dsn"
    postgres_ca = (tmp_path / "postgres-ca.crt").resolve()
    postgres_ca.write_text("fixture-ca", encoding="utf-8")
    postgres_dsn_file.write_text(
        "postgresql://worker@postgres/runtime"
        f"?sslmode=verify-full&sslrootcert={postgres_ca.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable\n",
        encoding="utf-8",
    )
    os.chmod(postgres_dsn_file, 0o440)
    monkeypatch.setenv("HALLU_DEFENSE_POSTGRES_DSN_FILE", str(postgres_dsn_file))
    monkeypatch.setenv("HALLU_DEFENSE_POSTGRES_CA_CERT_PATH", str(postgres_ca))
    monkeypatch.setenv("HALLU_DEFENSE_INGESTION_MODE", INGESTION_MODE_ASYNC)
    monkeypatch.setenv("HALLU_DEFENSE_AUDIT_LEDGER_BACKEND", "postgres")
    monkeypatch.setenv("HALLU_DEFENSE_CORPUS_GRANTS_BACKEND", "postgres")
    monkeypatch.setenv("HALLU_DEFENSE_RAG_INDEX_BACKEND", "hybrid")
    monkeypatch.setenv("HALLU_DEFENSE_OPENSEARCH_ENDPOINT", "https://search.example.test")
    monkeypatch.setenv(
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME",
        "rag/opensearch/authorization",
    )
    monkeypatch.setenv("HALLU_DEFENSE_SECRETS_BACKEND", "vault")
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_ADDR", "https://vault.example.test")
    vault_token_file = tmp_path / "vault-token"
    vault_token_file.write_text("guard-value\n", encoding="utf-8")
    os.chmod(vault_token_file, 0o440)
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_TOKEN_FILE", str(vault_token_file))
    vault_ca = tmp_path / "vault-ca.crt"
    opensearch_ca = tmp_path / "opensearch-ca.crt"
    vault_ca.write_text("fixture-ca", encoding="utf-8")
    opensearch_ca.write_text("fixture-ca", encoding="utf-8")
    monkeypatch.setenv("HALLU_DEFENSE_VAULT_CA_CERT_PATH", str(vault_ca))
    monkeypatch.setenv("HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH", str(opensearch_ca))
    monkeypatch.setenv("HALLU_DEFENSE_INGESTION_WORKER_ID", "pod-uid-1")
    monkeypatch.setenv(
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS",
        "https://search.example.test,https://vault.example.test",
    )

    settings = load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)

    assert settings.runtime_role == RUNTIME_ROLE_WORKER
    assert settings.auth_required is False
    assert settings.secrets_backend == "vault"
    assert settings.provider_backend == "mock"
    assert settings.sandbox_backend == "docker"


@pytest.mark.parametrize(
    ("missing_setting", "message"),
    [
        ("HALLU_DEFENSE_VAULT_TOKEN_FILE", "VAULT_TOKEN_FILE"),
        ("HALLU_DEFENSE_VAULT_CA_CERT_PATH", "VAULT_CA_CERT_PATH"),
    ],
)
def test_production_worker_fails_early_without_vault_runtime_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_setting: str,
    message: str,
) -> None:
    vault_ca = tmp_path / "vault-ca.crt"
    opensearch_ca = tmp_path / "opensearch-ca.crt"
    vault_ca.write_text("fixture-ca", encoding="utf-8")
    opensearch_ca.write_text("fixture-ca", encoding="utf-8")
    postgres_dsn_file = tmp_path / "postgres-dsn"
    postgres_ca = (tmp_path / "postgres-ca.crt").resolve()
    vault_token_file = tmp_path / "vault-token"
    postgres_ca.write_text("fixture-ca", encoding="utf-8")
    postgres_dsn_file.write_text(
        "postgresql://worker@postgres/runtime"
        f"?sslmode=verify-full&sslrootcert={postgres_ca.as_posix()}"
        "&ssl_min_protocol_version=TLSv1.3&gssencmode=disable\n",
        encoding="utf-8",
    )
    vault_token_file.write_text("guard-value\n", encoding="utf-8")
    os.chmod(postgres_dsn_file, 0o440)
    os.chmod(vault_token_file, 0o440)
    values = {
        "HALLU_DEFENSE_ENV": "production",
        "HALLU_DEFENSE_RUNTIME_ROLE": RUNTIME_ROLE_WORKER,
        "HALLU_DEFENSE_POSTGRES_DSN_FILE": str(postgres_dsn_file),
        "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH": str(postgres_ca),
        "HALLU_DEFENSE_INGESTION_MODE": INGESTION_MODE_ASYNC,
        "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND": "postgres",
        "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND": "postgres",
        "HALLU_DEFENSE_RAG_INDEX_BACKEND": "hybrid",
        "HALLU_DEFENSE_OPENSEARCH_ENDPOINT": "https://search.example.test",
        "HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME": ("rag/opensearch/authorization"),
        "HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH": str(opensearch_ca),
        "HALLU_DEFENSE_SECRETS_BACKEND": "vault",
        "HALLU_DEFENSE_VAULT_ADDR": "https://vault.example.test",
        "HALLU_DEFENSE_VAULT_TOKEN_FILE": str(vault_token_file),
        "HALLU_DEFENSE_VAULT_CA_CERT_PATH": str(vault_ca),
        "HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS": (
            "https://search.example.test,https://vault.example.test"
        ),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(missing_setting)

    with pytest.raises(RuntimeRoleConfigurationError, match=message):
        load_settings(expected_runtime_role=RUNTIME_ROLE_WORKER)


def test_api_executable_rejects_worker_role_before_reduced_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HALLU_DEFENSE_RUNTIME_ROLE", RUNTIME_ROLE_WORKER)

    with pytest.raises(RuntimeRoleConfigurationError, match="executable runtime role"):
        load_settings(expected_runtime_role=RUNTIME_ROLE_API)


def test_worker_role_rejects_nonpersistent_runtime_dependencies() -> None:
    settings = _settings(
        environment="production",
        runtime_role=RUNTIME_ROLE_WORKER,
        ingestion_mode=INGESTION_MODE_ASYNC,
        postgres_dsn="postgresql://worker@postgres/runtime",
        audit_ledger_backend="memory",
        corpus_grants_backend="memory",
        rag_index_backend="local",
    )

    with pytest.raises(RuntimeRoleConfigurationError) as exc_info:
        validate_worker_runtime_settings(settings)

    assert "audit ledger" in str(exc_info.value)
    assert "corpus grants" in str(exc_info.value)
    assert "persistent RAG" in str(exc_info.value)


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
        heartbeat_seconds=5,
        backfill_page_size=10,
    )

    assert worker.run_once() == 1

    assert queue.completed == [("ing_abc", "tenant-a", "worker-1", "lease-current")]
    assert ingestor.requests[0].corpus_id == "hr"
    events = audit.export_events(tenant_id="tenant-a")
    event_types = [event.event_type for event in events]
    assert "ingestion_job_claimed" in event_types
    assert "ingestion_job_succeeded" in event_types
    succeeded_event = next(
        event for event in events if event.event_type == "ingestion_job_succeeded"
    )
    assert succeeded_event.outcome == "succeeded"
    assert succeeded_event.metadata["job_status"] == "succeeded"
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
        heartbeat_seconds=5,
        backfill_page_size=10,
    )

    worker.run_once()

    assert queue.failed == [("ing_abc", "tenant-a", "worker-1", "lease-current", "RuntimeError")]
    assert [event.event_type for event in audit.export_events(tenant_id="tenant-a")] == [
        "ingestion_job_claimed",
        "ingestion_job_dead",
    ]


def test_hybrid_transport_failure_remains_a_durable_reconciliation_intent() -> None:
    queue = WorkerQueue(claimed=[_job()])
    audit = AuditLedger()
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=TransportFailingIngestor(),  # type: ignore[arg-type]
        audit=audit,
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        heartbeat_seconds=5,
        backfill_page_size=10,
        preserve_hybrid_write_intents=True,
    )

    assert worker.run_once() == 1

    assert queue.failed == []
    assert queue.retried == [
        (
            "ing_abc",
            "tenant-a",
            "worker-1",
            "lease-current",
            "RagIndexTransportError",
        )
    ]
    assert queue.requeue_calls == [True]
    assert [event.event_type for event in audit.export_events(tenant_id="tenant-a")] == [
        "ingestion_job_claimed",
        "ingestion_job_failed",
    ]


def test_hybrid_transport_failure_is_not_overwritten_by_heartbeat_failure() -> None:
    queue = WorkerQueue(
        claimed=[_job()],
        heartbeat_error=RuntimeError("database heartbeat unavailable"),
    )
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=SlowTransportFailingIngestor(0.03),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=1,
        heartbeat_seconds=0.005,
        backfill_page_size=10,
        preserve_hybrid_write_intents=True,
    )

    assert worker.run_once() == 1
    assert queue.failed == []
    assert queue.retried[-1][-1] == "RagIndexTransportError"


def test_hybrid_heartbeat_or_completion_uncertainty_preserves_write_intent() -> None:
    heartbeat_queue = WorkerQueue(
        claimed=[_job()],
        heartbeat_error=RuntimeError("database heartbeat unavailable"),
    )
    heartbeat_worker = IngestionWorker(
        queue=heartbeat_queue,  # type: ignore[arg-type]
        ingestor=SlowIngestor(0.03),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=1,
        heartbeat_seconds=0.005,
        backfill_page_size=10,
        preserve_hybrid_write_intents=True,
    )
    completion_queue = WorkerQueue(
        claimed=[_job()],
        complete_error=RuntimeError("completion result unknown"),
    )
    completion_worker = IngestionWorker(
        queue=completion_queue,  # type: ignore[arg-type]
        ingestor=RecordingIngestor(),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        heartbeat_seconds=5,
        backfill_page_size=10,
        preserve_hybrid_write_intents=True,
    )

    assert heartbeat_worker.run_once() == 1
    assert completion_worker.run_once() == 1
    assert heartbeat_queue.failed == []
    assert heartbeat_queue.retried[-1][-1] == "IngestionLeaseHeartbeatError"
    assert completion_queue.transition_order == ["complete", "retry"]
    assert completion_queue.failed == []


def test_hybrid_deterministic_failure_still_uses_bounded_dead_letter() -> None:
    dead = _job(status=IngestionJobStatus.DEAD, attempts=5)
    queue = WorkerQueue(claimed=[_job()], failed_job=dead)
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=FailingIngestor(),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        heartbeat_seconds=5,
        backfill_page_size=10,
        preserve_hybrid_write_intents=True,
    )

    assert worker.run_once() == 1
    assert queue.retried == []
    assert queue.failed == [("ing_abc", "tenant-a", "worker-1", "lease-current", "RuntimeError")]


def test_worker_discards_tombstoned_inflight_job_without_recreating_tenant_data() -> None:
    job = _job()
    queue = WorkerQueue(claimed=[job])
    audit = AuditLedger()
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=TombstonedTenantIngestor(),  # type: ignore[arg-type]
        audit=audit,
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        heartbeat_seconds=5,
        backfill_page_size=10,
    )

    assert worker.run_once() == 1
    assert queue.completed == []
    assert queue.failed == []
    assert [event.event_type for event in audit.export_events(tenant_id="tenant-a")] == [
        "ingestion_job_claimed"
    ]


def test_worker_processes_reindex_job() -> None:
    job = _job(
        job_type=IngestionJobType.REINDEX_CORPUS, payload={"corpus_id": "hr", "page_size": 25}
    )
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
        heartbeat_seconds=5,
        backfill_page_size=10,
        reindexer=reindexer,  # type: ignore[arg-type]
    )

    worker.run_once()

    assert reindexer.calls == [("tenant-a", "hr", 25)]
    assert queue.completed == [("ing_abc", "tenant-a", "worker-1", "lease-current")]


@pytest.mark.parametrize("failing_telemetry", ["audit", "metrics"])
def test_post_complete_telemetry_failure_does_not_fail_terminal_job(
    monkeypatch: pytest.MonkeyPatch,
    failing_telemetry: str,
) -> None:
    queue = WorkerQueue(claimed=[_job()])
    audit = AuditLedger()
    metrics = _metrics()
    if failing_telemetry == "audit":
        original_append = audit.append_event

        def append_event(**kwargs: Any) -> object:
            if kwargs.get("event_type") == "ingestion_job_succeeded":
                raise RuntimeError("audit unavailable")
            return original_append(**kwargs)

        monkeypatch.setattr(audit, "append_event", append_event)
    else:

        def record_ingestion_job(**kwargs: object) -> None:
            del kwargs
            raise RuntimeError("metrics unavailable")

        monkeypatch.setattr(metrics, "record_ingestion_job", record_ingestion_job)

    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=RecordingIngestor(),  # type: ignore[arg-type]
        audit=audit,
        metrics=metrics,
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        heartbeat_seconds=5,
        backfill_page_size=10,
    )

    assert worker.run_once() == 1
    assert queue.completed == [("ing_abc", "tenant-a", "worker-1", "lease-current")]
    assert queue.failed == []


def test_worker_renews_lease_and_stops_heartbeat_before_complete() -> None:
    queue = WorkerQueue(claimed=[_job()])
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=SlowIngestor(0.04),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=1,
        heartbeat_seconds=0.005,
        backfill_page_size=10,
    )

    assert worker.run_once() == 1
    assert queue.heartbeat_calls
    assert queue.transition_order[-1] == "complete"
    heartbeat_count = len(queue.heartbeat_calls)
    time.sleep(0.02)
    assert len(queue.heartbeat_calls) == heartbeat_count


def test_worker_claims_each_job_just_in_time() -> None:
    queue = WorkerQueue(claimed=[_job(), _job()])
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=RecordingIngestor(),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=2,
        poll_seconds=0.1,
        lock_timeout_seconds=60,
        heartbeat_seconds=5,
        backfill_page_size=10,
    )

    assert worker.run_once() == 2
    assert queue.claim_batch_sizes == [1, 1]


def test_worker_heartbeat_failure_forbids_terminal_success() -> None:
    queue = WorkerQueue(
        claimed=[_job()],
        heartbeat_error=RuntimeError("database heartbeat unavailable"),
    )
    worker = IngestionWorker(
        queue=queue,  # type: ignore[arg-type]
        ingestor=SlowIngestor(0.03),  # type: ignore[arg-type]
        audit=AuditLedger(),
        metrics=_metrics(),
        worker_id="worker-1",
        batch_size=1,
        poll_seconds=0.1,
        lock_timeout_seconds=1,
        heartbeat_seconds=0.005,
        backfill_page_size=10,
    )

    assert worker.run_once() == 1
    assert queue.heartbeat_calls
    assert queue.completed == []
    assert queue.failed == [
        (
            "ing_abc",
            "tenant-a",
            "worker-1",
            "lease-current",
            "IngestionLeaseHeartbeatError",
        )
    ]


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
        heartbeat_error: Exception | None = None,
        complete_error: Exception | None = None,
    ) -> None:
        self._claimed = list(claimed)
        self._failed_job = failed_job
        self._heartbeat_error = heartbeat_error
        self._complete_error = complete_error
        self.completed: list[tuple[str, str, str, str]] = []
        self.failed: list[tuple[str, str, str, str, str]] = []
        self.retried: list[tuple[str, str, str, str, str]] = []
        self.requeue_calls: list[bool] = []
        self.heartbeat_calls: list[tuple[str, str, str, str]] = []
        self.transition_order: list[str] = []
        self.claim_batch_sizes: list[int] = []

    def requeue_stale_running(self, **kwargs: object) -> list[IngestionJob]:
        self.requeue_calls.append(bool(kwargs.get("preserve_for_reconciliation")))
        return []

    def claim_batch(self, *, worker_id: str, batch_size: int) -> list[IngestionJob]:
        del worker_id
        self.claim_batch_sizes.append(batch_size)
        claimed = self._claimed[:batch_size]
        del self._claimed[:batch_size]
        return claimed

    def complete(
        self,
        *,
        job_id: str,
        tenant_id: str,
        worker_id: str,
        lease_token: str,
    ) -> IngestionJob:
        self.transition_order.append("complete")
        if self._complete_error is not None:
            raise self._complete_error
        self.completed.append((job_id, tenant_id, worker_id, lease_token))
        return _job(status=IngestionJobStatus.SUCCEEDED)

    def heartbeat(
        self,
        *,
        job_id: str,
        tenant_id: str,
        worker_id: str,
        lease_token: str,
    ) -> IngestionJob:
        self.transition_order.append("heartbeat")
        self.heartbeat_calls.append((job_id, tenant_id, worker_id, lease_token))
        if self._heartbeat_error is not None:
            raise self._heartbeat_error
        return _job()

    def fail(
        self,
        *,
        job_id: str,
        tenant_id: str,
        worker_id: str,
        lease_token: str,
        error: str,
    ) -> IngestionJob:
        self.transition_order.append("fail")
        self.failed.append((job_id, tenant_id, worker_id, lease_token, error))
        return self._failed_job or _job(status=IngestionJobStatus.FAILED, attempts=1)

    def retry_for_reconciliation(
        self,
        *,
        job_id: str,
        tenant_id: str,
        worker_id: str,
        lease_token: str,
        error: str,
    ) -> IngestionJob:
        self.transition_order.append("retry")
        self.retried.append((job_id, tenant_id, worker_id, lease_token, error))
        return _job(status=IngestionJobStatus.FAILED, attempts=99)


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


class TransportFailingIngestor:
    def ingest_prepared(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RagIndexTransportError("partial hybrid write")


class SlowTransportFailingIngestor:
    def __init__(self, delay_seconds: float) -> None:
        self._delay_seconds = delay_seconds

    def ingest_prepared(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        time.sleep(self._delay_seconds)
        raise RagIndexTransportError("partial hybrid write")


class TombstonedTenantIngestor:
    def ingest_prepared(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RagIndexTenantDeletedError(
            "Persistent RAG write is blocked for a durably deleted tenant."
        )


class SlowIngestor(RecordingIngestor):
    def __init__(self, delay_seconds: float) -> None:
        super().__init__()
        self._delay_seconds = delay_seconds

    def ingest_prepared(self, *args: Any, **kwargs: Any) -> object:
        time.sleep(self._delay_seconds)
        return super().ingest_prepared(*args, **kwargs)


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
        lease_token="lease-current" if status is IngestionJobStatus.RUNNING else None,
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
