from __future__ import annotations

import pytest

from scripts.ci.check_ingestion_pipeline_config import (
    IngestionPipelineConfigError,
    load_current_config,
    load_current_live_config,
    load_current_runtime_config,
    validate_ingestion_pipeline_config,
)


def test_ingestion_pipeline_config_validates_current_repo_state() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    config_text, worker_text, live_smoke_text = load_current_runtime_config()
    live_workflow_text, live_smoke_doc_text = load_current_live_config()

    validate_ingestion_pipeline_config(
        migration_sql=migration_sql,
        service_text=service_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        config_text=config_text,
        worker_text=worker_text,
        live_smoke_text=live_smoke_text,
        live_workflow_text=live_workflow_text,
        live_smoke_doc_text=live_smoke_doc_text,
    )


def test_rejects_worker_without_clean_heartbeat_stop() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    config_text, worker_text, live_smoke_text = load_current_runtime_config()
    broken_worker = worker_text.replace("heartbeat.stop()", "heartbeat.failure")

    with pytest.raises(IngestionPipelineConfigError, match="heartbeat.stop"):
        validate_ingestion_pipeline_config(
            migration_sql=migration_sql,
            service_text=service_text,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
            config_text=config_text,
            worker_text=broken_worker,
            live_smoke_text=live_smoke_text,
        )


def test_rejects_missing_status_available_at_index() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = migration_sql.replace("ON rag_ingestion_jobs (status, available_at)", "")

    with pytest.raises(IngestionPipelineConfigError, match="status, available_at"):
        validate_ingestion_pipeline_config(
            migration_sql=broken,
            service_text=service_text,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_config_without_production_async_ingestion_invariant() -> None:
    config_text, _worker_text, _live_smoke_text = load_current_runtime_config()
    broken = config_text.replace(
        "Production and staging require HALLU_DEFENSE_INGESTION_MODE=async.",
        "removed production async ingestion invariant",
    )

    with pytest.raises(IngestionPipelineConfigError, match="INGESTION_MODE=async"):
        _validate_current_live(config_text=broken)


def test_rejects_worker_without_durable_hybrid_reconciliation_retry() -> None:
    _config_text, worker_text, _live_smoke_text = load_current_runtime_config()
    broken = worker_text.replace(
        "self._queue.retry_for_reconciliation",
        "self._queue.fail",
    )

    with pytest.raises(IngestionPipelineConfigError, match="retry_for_reconciliation"):
        _validate_current_live(worker_text=broken)


def test_rejects_missing_lease_fencing_column() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = migration_sql.replace("ADD COLUMN IF NOT EXISTS lease_token text", "")

    with pytest.raises(IngestionPipelineConfigError, match="lease_token"):
        validate_ingestion_pipeline_config(
            migration_sql=broken,
            service_text=service_text,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_migration_with_drop_table() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    dropped = migration_sql + "\nDROP TABLE rag_ingestion_jobs;\n"

    with pytest.raises(IngestionPipelineConfigError, match="DROP TABLE"):
        validate_ingestion_pipeline_config(
            migration_sql=dropped,
            service_text=service_text,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_service_missing_skip_locked() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = service_text.replace("FOR UPDATE SKIP LOCKED", "FOR UPDATE")

    with pytest.raises(IngestionPipelineConfigError, match="FOR UPDATE SKIP LOCKED"):
        validate_ingestion_pipeline_config(
            migration_sql=migration_sql,
            service_text=broken,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_service_missing_dead_letter_status() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = service_text.replace("IngestionJobStatus.DEAD", "IngestionJobStatus.QUEUED")

    with pytest.raises(IngestionPipelineConfigError, match="IngestionJobStatus.DEAD"):
        validate_ingestion_pipeline_config(
            migration_sql=migration_sql,
            service_text=broken,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_missing_makefile_wiring() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = makefile_text.replace("ingestion-pipeline-config:", "removed-target:")

    with pytest.raises(IngestionPipelineConfigError, match="Makefile"):
        validate_ingestion_pipeline_config(
            migration_sql=migration_sql,
            service_text=service_text,
            makefile_text=broken,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_missing_ci_wiring() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = ci_workflow_text.replace("check_ingestion_pipeline_config.py", "")

    with pytest.raises(IngestionPipelineConfigError, match="CI workflow"):
        validate_ingestion_pipeline_config(
            migration_sql=migration_sql,
            service_text=service_text,
            makefile_text=makefile_text,
            ci_workflow_text=broken,
            security_workflow_text=security_workflow_text,
        )


def test_rejects_missing_security_workflow_wiring() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    broken = security_workflow_text.replace("check_ingestion_pipeline_config.py", "")

    with pytest.raises(IngestionPipelineConfigError, match="security workflow"):
        validate_ingestion_pipeline_config(
            migration_sql=migration_sql,
            service_text=service_text,
            makefile_text=makefile_text,
            ci_workflow_text=ci_workflow_text,
            security_workflow_text=broken,
        )


def test_rejects_live_smoke_without_real_worker_subprocess() -> None:
    _config_text, _worker_text, live_smoke_text = load_current_runtime_config()
    broken = live_smoke_text.replace("subprocess.Popen(", "subprocess.call(")

    with pytest.raises(IngestionPipelineConfigError, match="subprocess.Popen"):
        _validate_current_live(live_smoke_text=broken)


def test_rejects_live_smoke_without_real_pgvector_barrier() -> None:
    _config_text, _worker_text, live_smoke_text = load_current_runtime_config()
    broken = live_smoke_text.replace(
        "pg_advisory_lock(hashtextextended(%s, 0))",
        "removed_advisory_lock",
    )

    with pytest.raises(IngestionPipelineConfigError, match="pg_advisory_lock"):
        _validate_current_live(live_smoke_text=broken)


def test_rejects_live_smoke_that_migrates_admin_database() -> None:
    _config_text, _worker_text, live_smoke_text = load_current_runtime_config()
    broken = live_smoke_text.replace(
        "PsycopgMigrationConnection(dsn=scratch.dsn)",
        "PsycopgMigrationConnection(dsn=admin_dsn)",
    )

    with pytest.raises(IngestionPipelineConfigError, match="scratch.dsn"):
        _validate_current_live(live_smoke_text=broken)


def test_rejects_live_smoke_with_controller_side_requeue() -> None:
    _config_text, _worker_text, live_smoke_text = load_current_runtime_config()
    broken = live_smoke_text + "\nqueue.requeue_stale_running(locked_before=cutoff)\n"

    with pytest.raises(IngestionPipelineConfigError, match="real worker orchestration"):
        _validate_current_live(live_smoke_text=broken)


def test_rejects_live_smoke_with_manufactured_future_cutoff() -> None:
    _config_text, _worker_text, live_smoke_text = load_current_runtime_config()
    broken = live_smoke_text + (
        "\ncutoff = datetime.now(timezone.utc) + timedelta(seconds=300)\n"
    )

    with pytest.raises(IngestionPipelineConfigError, match="future stale cutoff"):
        _validate_current_live(live_smoke_text=broken)


def test_rejects_live_smoke_that_serializes_an_untyped_exception_detail() -> None:
    _config_text, _worker_text, live_smoke_text = load_current_runtime_config()
    broken = live_smoke_text + '\nfailure["raw_error"] = str(exc)\n'

    with pytest.raises(IngestionPipelineConfigError, match="sanitized, typed"):
        _validate_current_live(live_smoke_text=broken)


def test_rejects_live_workflow_that_can_silently_skip_smoke() -> None:
    live_workflow_text, _live_smoke_doc_text = load_current_live_config()
    broken = live_workflow_text.replace(
        'HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED: "true"',
        'HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED: "false"',
    )

    with pytest.raises(IngestionPipelineConfigError, match="must not contain"):
        _validate_current_live(live_workflow_text=broken)


def test_rejects_live_workflow_global_compose_teardown() -> None:
    live_workflow_text, _live_smoke_doc_text = load_current_live_config()
    broken = live_workflow_text.replace(
        "docker compose stop postgres || true",
        "docker compose down -v || true",
        1,
    )

    with pytest.raises(IngestionPipelineConfigError, match="docker compose down"):
        _validate_current_live(live_workflow_text=broken)


def test_rejects_live_workflow_that_leaves_project_network() -> None:
    live_workflow_text, _live_smoke_doc_text = load_current_live_config()
    broken = live_workflow_text.replace(
        'docker network rm "${COMPOSE_PROJECT_NAME}_default" || true',
        "",
    )

    with pytest.raises(IngestionPipelineConfigError, match="docker network rm"):
        _validate_current_live(live_workflow_text=broken)


def test_rejects_live_smoke_docs_without_scratch_isolation() -> None:
    _live_workflow_text, live_smoke_doc_text = load_current_live_config()
    broken = live_smoke_doc_text.replace("scratch database", "temporary schema")

    with pytest.raises(IngestionPipelineConfigError, match="scratch database"):
        _validate_current_live(live_smoke_doc_text=broken)


def _validate_current_live(
    *,
    config_text: str | None = None,
    worker_text: str | None = None,
    live_smoke_text: str | None = None,
    live_workflow_text: str | None = None,
    live_smoke_doc_text: str | None = None,
) -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )
    current_config, current_worker, current_live_smoke = load_current_runtime_config()
    current_live_workflow, current_live_doc = load_current_live_config()
    validate_ingestion_pipeline_config(
        migration_sql=migration_sql,
        service_text=service_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        config_text=config_text or current_config,
        worker_text=worker_text or current_worker,
        live_smoke_text=live_smoke_text or current_live_smoke,
        live_workflow_text=live_workflow_text or current_live_workflow,
        live_smoke_doc_text=live_smoke_doc_text or current_live_doc,
    )
