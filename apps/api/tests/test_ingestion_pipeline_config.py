from __future__ import annotations

import pytest

from scripts.ci.check_ingestion_pipeline_config import (
    IngestionPipelineConfigError,
    load_current_config,
    validate_ingestion_pipeline_config,
)


def test_ingestion_pipeline_config_validates_current_repo_state() -> None:
    migration_sql, service_text, makefile_text, ci_workflow_text, security_workflow_text = (
        load_current_config()
    )

    validate_ingestion_pipeline_config(
        migration_sql=migration_sql,
        service_text=service_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
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
