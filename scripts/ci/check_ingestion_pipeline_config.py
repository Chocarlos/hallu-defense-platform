"""Fail-closed configuration gate for the durable ingestion pipeline.

The gate validates the PostgreSQL outbox and lease-fencing migrations, atomic
queue transitions, async runtime/worker/backfill invariants, the real
crash/restart smoke contract, and exact CI/security/live-workflow wiring.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTBOX_MIGRATION = ROOT / "infra" / "rag" / "pgvector" / "006_ingestion_outbox.sql"
LEASE_FENCING_MIGRATION = (
    ROOT / "infra" / "rag" / "pgvector" / "007_ingestion_lease_fencing.sql"
)
INGESTION_JOBS_SERVICE = (
    ROOT / "apps" / "api" / "src" / "hallu_defense" / "services" / "ingestion_jobs.py"
)
CONFIG_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "config.py"
WORKER_PATH = ROOT / "apps" / "api" / "src" / "hallu_defense" / "worker.py"
LIVE_SMOKE_PATH = ROOT / "scripts" / "dev" / "live_ingestion_worker_smoke.py"
LIVE_WORKFLOW = ROOT / ".github" / "workflows" / "live.yml"
LIVE_SMOKE_DOC = ROOT / "docs" / "rag" / "backfill.md"
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
    "ADD COLUMN IF NOT EXISTS lease_token text",
    "ON rag_ingestion_jobs (status, available_at)",
}

REQUIRED_SERVICE_SNIPPETS = {
    "class PostgresIngestionJobQueue",
    "FOR UPDATE SKIP LOCKED",
    "def enqueue(",
    "def claim_batch(",
    "def heartbeat(",
    "def complete(",
    "def fail(",
    "def retry_for_reconciliation(",
    "lease_token = %s",
    "AND lease_token = %s",
    "IngestionJobStatus.DEAD",
    "IngestionJobStatus.FAILED",
    "power(2, attempts)",
    "LEAST(attempts, 16)",
    "MAX_RECONCILIATION_BACKOFF_SECONDS",
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
    config_text: str | None = None,
    worker_text: str | None = None,
    live_smoke_text: str | None = None,
    live_workflow_text: str | None = None,
    live_smoke_doc_text: str | None = None,
) -> None:
    errors: list[str] = []
    _validate_migration(migration_sql, errors)
    _validate_service(service_text, errors)
    if config_text is not None or worker_text is not None or live_smoke_text is not None:
        _validate_runtime(
            config_text=config_text or "",
            worker_text=worker_text or "",
            live_smoke_text=live_smoke_text or "",
            errors=errors,
        )
    if live_workflow_text is not None or live_smoke_doc_text is not None:
        _validate_live_wiring(
            live_workflow_text=live_workflow_text or "",
            live_smoke_doc_text=live_smoke_doc_text or "",
            errors=errors,
        )
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
        OUTBOX_MIGRATION.read_text(encoding="utf-8")
        + "\n"
        + LEASE_FENCING_MIGRATION.read_text(encoding="utf-8"),
        INGESTION_JOBS_SERVICE.read_text(encoding="utf-8"),
        MAKEFILE.read_text(encoding="utf-8"),
        CI_WORKFLOW.read_text(encoding="utf-8"),
        SECURITY_WORKFLOW.read_text(encoding="utf-8"),
    )


def load_current_runtime_config() -> tuple[str, str, str]:
    return (
        CONFIG_PATH.read_text(encoding="utf-8"),
        WORKER_PATH.read_text(encoding="utf-8"),
        LIVE_SMOKE_PATH.read_text(encoding="utf-8"),
    )


def load_current_live_config() -> tuple[str, str]:
    return (
        LIVE_WORKFLOW.read_text(encoding="utf-8"),
        LIVE_SMOKE_DOC.read_text(encoding="utf-8"),
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


def _validate_runtime(
    *,
    config_text: str,
    worker_text: str,
    live_smoke_text: str,
    errors: list[str],
) -> None:
    for marker in (
        "HALLU_DEFENSE_INGESTION_WORKER_HEARTBEAT_SECONDS",
        "ingestion_worker_heartbeat_seconds",
        "HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS",
        "Production and staging require HALLU_DEFENSE_INGESTION_MODE=async.",
    ):
        if marker not in config_text:
            errors.append(f"config.py missing heartbeat invariant {marker!r}")
    for marker in (
        "class IngestionLeaseHeartbeat",
        "def stop(",
        ".heartbeat(",
        "heartbeat.stop()",
        "heartbeat_failure",
        "batch_size=1",
        "preserve_hybrid_write_intents",
        "isinstance(error, RagIndexTransportError)",
        "self._queue.retry_for_reconciliation",
    ):
        if marker not in worker_text:
            errors.append(f"worker.py missing heartbeat safeguard {marker!r}")
    for marker in (
        'WORKER_MODULE_COMMAND = ("-m", "hallu_defense.worker", "--once")',
        "subprocess.Popen(",
        "class ScratchDatabase",
        "scratch.create()",
        "PsycopgMigrationConnection(dsn=scratch.dsn)",
        "provider.close()",
        "scratch.drop()",
        'parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}',
        "class AdvisoryWriteBarrier",
        "pg_advisory_lock(hashtextextended(%s, 0))",
        "pg_stat_activity",
        "process.kill()",
        "SELECT clock_timestamp() AS database_now",
        "_assert_old_lease_rejected(",
        "queue.heartbeat(",
        "queue.complete(",
        "queue.fail(",
        "new_token == old_token",
        "terminal_audits != 1 or success_audits != 1",
        "_smoke_footprint_count(",
        '"scratch_database_removed": True',
        '"error_type": type(exc).__name__',
        "if isinstance(exc, LiveIngestionWorkerSmokeError):",
        'failure["error"] = str(exc)',
    ):
        if marker not in live_smoke_text:
            errors.append(f"live_ingestion_worker_smoke.py missing live proof {marker!r}")
    for forbidden in (
        "_run_heartbeat_probe",
        "_run_fencing_probe",
        "queue.claim_batch(",
        "queue.requeue_stale_running(",
    ):
        if forbidden in live_smoke_text:
            errors.append(
                "live_ingestion_worker_smoke.py must use real worker orchestration; "
                f"found {forbidden!r}"
            )
    if re.search(
        r"datetime\.now\([^\n]*\)\s*\+\s*timedelta\(",
        live_smoke_text,
    ):
        errors.append(
            "live_ingestion_worker_smoke.py must not manufacture a future stale cutoff"
        )
    if live_smoke_text.count("str(exc)") != 1:
        errors.append(
            "live_ingestion_worker_smoke.py may serialize only the sanitized, typed "
            "LiveIngestionWorkerSmokeError detail"
        )


def _validate_live_wiring(
    *,
    live_workflow_text: str,
    live_smoke_doc_text: str,
    errors: list[str],
) -> None:
    job_name = "ingestion-worker-crash-recovery-live"
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\s*\n"
        r"(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*(?:#.*)?$|\Z)",
        live_workflow_text,
    )
    if match is None:
        errors.append(f"live workflow missing mandatory `{job_name}` job")
    else:
        job_text = match.group("body")
        required_markers = (
            "timeout-minutes:",
            "COMPOSE_PROJECT_NAME: hallu-ingestion-${{ github.run_id }}-${{ github.run_attempt }}",
            "docker compose up -d postgres",
            "docker compose exec -T postgres pg_isready",
            'HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED: "true"',
            "HALLU_DEFENSE_POSTGRES_DSN: postgresql://",
            "HALLU_DEFENSE_RAG_INDEX_BACKEND: pgvector",
            "HALLU_DEFENSE_AUDIT_LEDGER_BACKEND: postgres",
            "HALLU_DEFENSE_CORPUS_GRANTS_BACKEND: postgres",
            "HALLU_DEFENSE_INGESTION_MODE: async",
            "python scripts/dev/live_ingestion_worker_smoke.py",
            "if: always()",
            "docker compose stop postgres",
            "docker compose rm -f postgres",
            'docker volume rm "${COMPOSE_PROJECT_NAME}_postgres-data"',
            'docker network rm "${COMPOSE_PROJECT_NAME}_default"',
        )
        for marker in required_markers:
            if marker not in job_text:
                errors.append(f"live ingestion worker job missing {marker!r}")
        for forbidden in (
            "continue-on-error:",
            "docker compose down",
            "HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED: ${{",
            'HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED: "false"',
        ):
            if forbidden in job_text:
                errors.append(f"live ingestion worker job must not contain {forbidden!r}")

    required_doc_markers = (
        "scratch database",
        "main database migration ledger",
        "worker a",
        "worker b",
        "session-level postgresql advisory lock",
        "real postgresql clock",
        "same worker id",
        "heartbeat, completion, and failure",
        "exactly one chunk",
        "no footprint",
        ".github/workflows/live.yml",
    )
    normalized_doc = re.sub(r"\s+", " ", live_smoke_doc_text.lower())
    for marker in required_doc_markers:
        if marker not in normalized_doc:
            errors.append(f"live ingestion worker documentation missing {marker!r}")


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
    print("Validated durable ingestion pipeline and live recovery configuration.")


if __name__ == "__main__":
    main()
