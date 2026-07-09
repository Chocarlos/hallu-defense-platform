"""Initial storage-layer config gate for the durable ingestion outbox (Batch 6).

Scope note: this gate only validates the PostgreSQL outbox storage slice --
the `006_ingestion_outbox.sql` migration shape, the `ingestion_jobs.py`
queue's atomic claim/complete/fail SQL, and Makefile/CI/security wiring for
this script itself. Async ingestion mode, the `/documents/ingest/status`
endpoint, the worker process, and backfill/reindex are separate slices with
their own gates layered on top of this one.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTBOX_MIGRATION = ROOT / "infra" / "rag" / "pgvector" / "006_ingestion_outbox.sql"
INGESTION_JOBS_SERVICE = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "ingestion_jobs.py"
)
MAKEFILE = ROOT / "Makefile"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"

REQUIRED_MIGRATION_SNIPPETS = {
    "CREATE TABLE IF NOT EXISTS rag_ingestion_jobs",
    "job_id text PRIMARY KEY",
    "tenant_id text NOT NULL",
    "trace_id text NOT NULL",
    "job_type text NOT NULL",
    "payload jsonb NOT NULL",
    "status text NOT NULL",
    "attempts integer NOT NULL DEFAULT 0",
    "available_at timestamptz NOT NULL DEFAULT now()",
    "locked_by text",
    "locked_at timestamptz",
    "ON rag_ingestion_jobs (status, available_at)",
}

REQUIRED_SERVICE_SNIPPETS = {
    "class PostgresIngestionJobQueue",
    "FOR UPDATE SKIP LOCKED",
    "def enqueue(",
    "def claim_batch(",
    "def complete(",
    "def fail(",
    "IngestionJobStatus.DEAD",
    "IngestionJobStatus.FAILED",
    "power(2, attempts)",
}


class IngestionPipelineConfigError(ValueError):
    pass


def validate_ingestion_pipeline_config(
    *,
    migration_sql: str,
    service_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_migration(migration_sql, errors)
    _validate_service(service_text, errors)
    _validate_wiring(
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
        errors=errors,
    )
    if errors:
        raise IngestionPipelineConfigError("\n".join(errors))


def load_current_config() -> tuple[str, str, str, str, str]:
    return (
        OUTBOX_MIGRATION.read_text(encoding="utf-8"),
        INGESTION_JOBS_SERVICE.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )


def _validate_migration(sql: str, errors: list[str]) -> None:
    for snippet in REQUIRED_MIGRATION_SNIPPETS:
        if snippet not in sql:
            errors.append(f"ingestion outbox migration missing `{snippet}`")
    if re.search(r"(?i)DROP\s+TABLE", sql):
        errors.append("ingestion outbox migration must not contain DROP TABLE")
    if "IF NOT EXISTS" not in sql:
        errors.append("ingestion outbox migration must be idempotent (IF NOT EXISTS)")


def _validate_service(service_text: str, errors: list[str]) -> None:
    for snippet in REQUIRED_SERVICE_SNIPPETS:
        if snippet not in service_text:
            errors.append(f"ingestion_jobs.py missing `{snippet}`")
    if "RETURNING" not in service_text:
        errors.append("ingestion_jobs.py must guard state transitions with RETURNING")


def _validate_wiring(
    *,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    script = "scripts/ci/check_ingestion_pipeline_config.py"
    if "ingestion-pipeline-config:" not in makefile_text or script not in makefile_text:
        errors.append("Makefile must expose the ingestion-pipeline-config gate")
    if not _makefile_phony_includes(makefile_text, "ingestion-pipeline-config"):
        errors.append("Makefile .PHONY must include ingestion-pipeline-config")
    if script not in ci_workflow_text:
        errors.append("CI workflow must run check_ingestion_pipeline_config.py")
    if script not in security_workflow_text:
        errors.append("security workflow must run check_ingestion_pipeline_config.py")


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    for line in makefile_text.splitlines():
        if line.startswith(".PHONY:"):
            return target in line.split()
    return False


def main() -> None:
    (
        migration_sql,
        service_text,
        makefile_text,
        ci_workflow_text,
        security_workflow_text,
    ) = load_current_config()
    validate_ingestion_pipeline_config(
        migration_sql=migration_sql,
        service_text=service_text,
        makefile_text=makefile_text,
        ci_workflow_text=ci_workflow_text,
        security_workflow_text=security_workflow_text,
    )
    print("Validated ingestion pipeline storage configuration.")


if __name__ == "__main__":
    main()
