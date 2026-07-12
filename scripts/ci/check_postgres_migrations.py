from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "infra" / "rag" / "pgvector"
APPLIER_PATH = ROOT / "scripts" / "dev" / "apply_postgres_migrations.py"
TEST_PATH = ROOT / "apps" / "api" / "tests" / "test_apply_postgres_migrations.py"
DOC_PATH = ROOT / "docs" / "rag" / "postgres-migrations.md"
MAKEFILE_PATH = ROOT / "Makefile"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "security.yml"

EXPECTED_MIGRATIONS = (
    "000_schema_migrations.sql",
    "001_rag_evidence_chunks.sql",
    "002_rag_corpus_grants.sql",
    "003_audit_ledger.sql",
    "004_approval_queue.sql",
    "005_eval_reports.sql",
    "006_ingestion_outbox.sql",
    "007_ingestion_lease_fencing.sql",
    "008_schema_migration_checksums.sql",
    "009_drop_unsafe_ivfflat.sql",
    "010_add_retrieved_at.sql",
    "011_rag_lifecycle_outbox.sql",
    "012_rag_tenant_deletion_fence.sql",
    "013_audit_history_integrity.sql",
)
MIGRATION_NAME_PATTERN = re.compile(r"^[0-9]{3}_[a-z0-9_]+\.sql$")
GATE_SCRIPT = "scripts/ci/check_postgres_migrations.py"
GATE_TARGET = "postgres-migrations-check"


class PostgresMigrationsConfigError(ValueError):
    pass


def load_migration_texts(path: Path = MIGRATIONS_DIR) -> dict[str, str]:
    return {
        migration.name: migration.read_text(encoding="utf-8")
        for migration in sorted(path.glob("*.sql"))
    }


def validate_postgres_migrations(
    *,
    migration_texts: Mapping[str, str],
    applier_text: str,
    tests_text: str,
    docs_text: str,
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
) -> None:
    errors: list[str] = []
    _validate_migration_set(migration_texts, errors)
    _validate_ledger(
        migration_texts.get(EXPECTED_MIGRATIONS[0], ""),
        migration_texts.get("008_schema_migration_checksums.sql", ""),
        errors,
    )
    _validate_exact_vector_migration(
        migration_texts.get("009_drop_unsafe_ivfflat.sql", ""),
        errors,
    )
    _validate_retrieved_at_migration(
        migration_texts.get("010_add_retrieved_at.sql", ""),
        errors,
    )
    _validate_rag_lifecycle_outbox(
        migration_texts.get("011_rag_lifecycle_outbox.sql", ""),
        errors,
    )
    _validate_rag_tenant_deletion_fence(
        migration_texts.get("012_rag_tenant_deletion_fence.sql", ""),
        errors,
    )
    _validate_audit_history_integrity(
        migration_texts.get("013_audit_history_integrity.sql", ""),
        errors,
    )
    _validate_applier(applier_text, errors)
    _validate_tests(tests_text, errors)
    _validate_docs(docs_text, errors)
    _validate_wiring(makefile_text, ci_workflow_text, security_workflow_text, errors)
    if errors:
        raise PostgresMigrationsConfigError("\n".join(errors))


def _validate_migration_set(
    migration_texts: Mapping[str, str],
    errors: list[str],
) -> None:
    versions = tuple(sorted(migration_texts))
    if versions != EXPECTED_MIGRATIONS:
        errors.append(
            "PostgreSQL migration set must be exactly 000 through 013; found: "
            + ", ".join(versions)
        )
    for version, sql in migration_texts.items():
        if MIGRATION_NAME_PATTERN.fullmatch(version) is None:
            errors.append(f"migration filename is not ordered/safe: {version}")
        if not sql.strip():
            errors.append(f"migration must not be empty: {version}")


def _validate_ledger(
    bootstrap_sql: str,
    checksum_sql: str,
    errors: list[str],
) -> None:
    for marker in (
        "CREATE TABLE IF NOT EXISTS schema_migrations",
        "version text PRIMARY KEY",
    ):
        if marker not in bootstrap_sql:
            errors.append(f"000_schema_migrations.sql missing `{marker}`")
    if "checksum_sha256" in bootstrap_sql:
        errors.append(
            "000_schema_migrations.sql must remain immutable; add checksum changes in 008"
        )
    for marker in (
        "ALTER TABLE schema_migrations",
        "ADD COLUMN IF NOT EXISTS checksum_sha256 text",
    ):
        if marker not in checksum_sql:
            errors.append(f"008_schema_migration_checksums.sql missing `{marker}`")


def _validate_exact_vector_migration(sql: str, errors: list[str]) -> None:
    required = "DROP INDEX IF EXISTS idx_rag_evidence_chunks_embedding"
    if required not in sql:
        errors.append(f"009_drop_unsafe_ivfflat.sql missing `{required}`")
    if re.search(r"(?i)CREATE\s+INDEX.+(?:ivfflat|hnsw)", sql):
        errors.append(
            "009_drop_unsafe_ivfflat.sql must not create an approximate vector index"
        )


def _validate_retrieved_at_migration(sql: str, errors: list[str]) -> None:
    normalized = re.sub(r"\s+", " ", sql).strip()
    for marker in (
        "ADD COLUMN IF NOT EXISTS retrieved_at TIMESTAMPTZ",
        "SET retrieved_at = created_at",
        "WHERE retrieved_at IS NULL",
        "ALTER COLUMN retrieved_at SET NOT NULL",
    ):
        if marker not in normalized:
            errors.append(f"010_add_retrieved_at.sql missing `{marker}`")


def _validate_rag_lifecycle_outbox(sql: str, errors: list[str]) -> None:
    normalized = re.sub(r"\s+", " ", sql).strip()
    for marker in (
        "CREATE TABLE IF NOT EXISTS rag_lifecycle_operations",
        "operation_id text PRIMARY KEY",
        "operation_kind text NOT NULL",
        "target_tenant_id text",
        "evidence_cutoff timestamptz",
        "status IN ('pending', 'processing', 'external_deleted', 'completed')",
        "lease_token text",
        "external_deleted_count bigint NOT NULL DEFAULT 0",
        "WHERE status IN ('pending', 'processing', 'external_deleted')",
    ):
        if marker not in normalized:
            errors.append(f"011_rag_lifecycle_outbox.sql missing `{marker}`")


def _validate_rag_tenant_deletion_fence(sql: str, errors: list[str]) -> None:
    normalized = re.sub(r"\s+", " ", sql).strip()
    for marker in (
        "CREATE TABLE IF NOT EXISTS rag_tenant_deletion_tombstones",
        "tenant_id text PRIMARY KEY",
        "operation_id text NOT NULL REFERENCES rag_lifecycle_operations (operation_id)",
        "CREATE OR REPLACE FUNCTION hallu_reject_deleted_rag_tenant_write()",
        "WHERE tenant_id = NEW.tenant_id",
        "BEFORE INSERT OR UPDATE ON rag_evidence_chunks",
        "BEFORE INSERT OR UPDATE ON rag_ingestion_jobs",
        "ERRCODE = '42501'",
    ):
        if marker not in normalized:
            errors.append(f"012_rag_tenant_deletion_fence.sql missing `{marker}`")


def _validate_audit_history_integrity(sql: str, errors: list[str]) -> None:
    normalized = re.sub(r"\s+", " ", sql).strip()
    for marker in (
        "ADD COLUMN IF NOT EXISTS completion_path text",
        "DO $audit_replay_backfill$",
        "payload #>> '{input,replay_of}' = replay_row.source_trace_id",
        "payload ->> 'final_decision' = replay_row.replay_final_decision",
        "migrated_event_id := 'evt_migrated_completion_' || replay_row.id::text",
        "'event_type', 'verification_completed'",
        "audit replay legacy reconciliation found an orphaned or ambiguous triple",
        "DO $audit_history_backfill$",
        "run_count <> 1",
        "event_count <> 1",
        "UPDATE audit_runs AS legacy_run",
        "SET completion_path = completion.completion_path",
        "audit completion legacy backfill is orphaned, ambiguous",
        "audit completion run/event parity validation failed",
        "completed_run.final_decision IS DISTINCT FROM completion.final_decision",
        "audit replay run/completion/provenance parity validation failed",
        "replayed_run.source_trace_id IS DISTINCT FROM provenance.source_trace_id",
        "IS DISTINCT FROM provenance.replay_final_decision",
        "ALTER COLUMN checksum_sha256 SET NOT NULL",
        "DROP CONSTRAINT IF EXISTS ck_schema_migrations_checksum_sha256",
        "ADD CONSTRAINT ck_schema_migrations_checksum_sha256",
        "checksum_sha256 ~ '^[0-9a-f]{64}$'",
        "VALIDATE CONSTRAINT ck_schema_migrations_checksum_sha256",
        "DROP CONSTRAINT IF EXISTS ck_audit_runs_payload_envelope",
        "ADD CONSTRAINT ck_audit_runs_payload_envelope",
        "tenant_id = payload ->> 'tenant_id'",
        "trace_id = payload ->> 'trace_id'",
        "created_at = (payload ->> 'created_at')::timestamptz",
        "VALIDATE CONSTRAINT ck_audit_runs_payload_envelope",
        "DROP CONSTRAINT IF EXISTS ck_audit_runs_completion_contract",
        "ADD CONSTRAINT ck_audit_runs_completion_contract",
        "tenant_id = btrim(tenant_id)",
        "trace_id ~ '^tr_[A-Za-z0-9_-]{8,80}$'",
        "jsonb_typeof(payload #> '{input,replay_of}') = 'string'",
        "(payload #>> '{input,replay_of}') ~ '^tr_[A-Za-z0-9_-]{8,80}$'",
        "VALIDATE CONSTRAINT ck_audit_runs_completion_contract",
        "DROP CONSTRAINT IF EXISTS ck_audit_events_payload_envelope",
        "ADD CONSTRAINT ck_audit_events_payload_envelope",
        "event_id = payload ->> 'event_id'",
        "event_id ~ '^evt_[A-Za-z0-9_-]+$'",
        "VALIDATE CONSTRAINT ck_audit_events_payload_envelope",
        "DROP CONSTRAINT IF EXISTS ck_audit_events_verification_completed",
        "ADD CONSTRAINT ck_audit_events_verification_completed",
        'payload @> \'{"method":"POST","status_code":200,"outcome":"success"}\'::jsonb',
        "'/verification/run'",
        "'/v2/verification/run'",
        "'/verification/replay'",
        "payload #>> '{metadata,final_decision}'",
        "payload -> 'metadata' = jsonb_build_object( 'final_decision'",
        "VALIDATE CONSTRAINT ck_audit_events_verification_completed",
        "DROP CONSTRAINT IF EXISTS ck_audit_events_verification_replay",
        "ADD CONSTRAINT ck_audit_events_verification_replay",
        'payload @> \'{"method":"POST","path":"/verification/replay","status_code":200,"outcome":"success"}\'::jsonb',
        "jsonb_typeof(payload #> '{metadata,source_trace_id}') = 'string'",
        "(payload #>> '{metadata,source_trace_id}') ~ '^tr_[A-Za-z0-9_-]{8,80}$'",
        "payload #>> '{metadata,source_final_decision}' IN (",
        "jsonb_typeof(payload #> '{metadata,replay_final_decision}') = 'string'",
        "payload #>> '{metadata,replay_final_decision}' IN (",
        "jsonb_typeof(payload #> '{metadata,decision_changed}') = 'boolean'",
        "payload #> '{metadata,decision_changed}' = CASE",
        "WHEN (payload #>> '{metadata,source_final_decision}') <> (payload #>> '{metadata,replay_final_decision}')",
        "THEN 'true'::jsonb ELSE 'false'::jsonb END",
        "payload -> 'metadata' = jsonb_build_object( 'source_trace_id'",
        "VALIDATE CONSTRAINT ck_audit_events_verification_replay",
        "DROP INDEX IF EXISTS ix_audit_runs_tenant_created;",
        "DROP INDEX IF EXISTS ix_audit_runs_tenant_trace;",
        "DROP INDEX IF EXISTS ix_audit_events_tenant_created;",
        "DROP INDEX IF EXISTS ix_audit_events_tenant_trace;",
        "DROP INDEX IF EXISTS ux_audit_runs_tenant_trace_completion_path",
        "CREATE UNIQUE INDEX ux_audit_runs_tenant_trace_completion_path",
        "ON audit_runs (tenant_id, trace_id, completion_path)",
        "WHERE completion_path IS NOT NULL",
        "DROP INDEX IF EXISTS ux_audit_events_tenant_trace_completion_path",
        "CREATE UNIQUE INDEX ux_audit_events_tenant_trace_completion_path",
        "ON audit_events (tenant_id, trace_id, (payload ->> 'path'))",
        "WHERE payload ->> 'event_type' = 'verification_completed'",
        "DROP INDEX IF EXISTS ux_audit_events_tenant_trace_replay_path",
        "CREATE UNIQUE INDEX ux_audit_events_tenant_trace_replay_path",
        "WHERE payload ->> 'event_type' = 'verification_replay'",
        "DROP INDEX IF EXISTS ux_audit_events_tenant_event_id",
        "CREATE UNIQUE INDEX ux_audit_events_tenant_event_id",
        "ON audit_events (tenant_id, event_id)",
        "DROP INDEX IF EXISTS ix_audit_runs_created_id",
        "CREATE INDEX ix_audit_runs_created_id",
        "ON audit_runs (created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_runs_trace_created_id",
        "CREATE INDEX ix_audit_runs_trace_created_id",
        "ON audit_runs (trace_id, created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_runs_tenant_created_id",
        "CREATE INDEX ix_audit_runs_tenant_created_id",
        "ON audit_runs (tenant_id, created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_runs_tenant_trace_created_id",
        "CREATE INDEX ix_audit_runs_tenant_trace_created_id",
        "ON audit_runs (tenant_id, trace_id, created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_events_created_id",
        "CREATE INDEX ix_audit_events_created_id",
        "ON audit_events (created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_events_trace_created_id",
        "CREATE INDEX ix_audit_events_trace_created_id",
        "ON audit_events (trace_id, created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_events_tenant_created_id",
        "CREATE INDEX ix_audit_events_tenant_created_id",
        "ON audit_events (tenant_id, created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_events_tenant_trace_created_id",
        "CREATE INDEX ix_audit_events_tenant_trace_created_id",
        "ON audit_events (tenant_id, trace_id, created_at DESC, id DESC)",
        "DROP INDEX IF EXISTS ix_audit_events_tenant_type_created_event",
        "CREATE INDEX ix_audit_events_tenant_type_created_event",
        "(payload ->> 'event_type')",
        "created_at DESC",
        "event_id DESC",
        "DROP INDEX IF EXISTS ix_audit_events_tenant_type_trace_created_event",
        "CREATE INDEX ix_audit_events_tenant_type_trace_created_event",
        "trace_id",
    ):
        if marker not in normalized:
            errors.append(f"013_audit_history_integrity.sql missing `{marker}`")
    for destructive in ("DROP TABLE", "DELETE FROM", "TRUNCATE"):
        if destructive in normalized.upper():
            errors.append(
                "013_audit_history_integrity.sql must preserve audit data; found "
                f"`{destructive}`"
            )
    if re.search(
        r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+"
        r"(?:ux|ix)_audit_",
        normalized,
        flags=re.IGNORECASE,
    ):
        errors.append(
            "013 audit indexes must use transactional DROP/CREATE so a raw rerun "
            "repairs drifted definitions"
        )


def _validate_applier(applier_text: str, errors: list[str]) -> None:
    for marker in (
        "BOOTSTRAP_LEDGER_SQL =",
        "MIGRATION_LOCK_KEY =",
        "MIGRATION_LOCK_TIMEOUT_SQL = \"SET LOCAL lock_timeout = '30s'\"",
        "MIGRATION_STATEMENT_TIMEOUT_SQL = \"SET LOCAL statement_timeout = '14min'\"",
        "with connection.transaction() as transaction:",
        "transaction.execute(MIGRATION_LOCK_TIMEOUT_SQL)",
        "transaction.execute(MIGRATION_STATEMENT_TIMEOUT_SQL)",
        "SELECT pg_advisory_xact_lock(%s)",
        'hashlib.sha256(statement.encode("utf-8")).hexdigest()',
        "SELECT version, checksum_sha256 FROM schema_migrations",
        "recorded_checksum != checksum",
        "Database records migration versions missing from the repository",
        "INSERT INTO schema_migrations (version, checksum_sha256)",
        "WHERE version = %s AND checksum_sha256 IS NULL",
    ):
        if marker not in applier_text:
            errors.append(f"migration applier missing `{marker}`")

    transaction_adapter = applier_text.partition(
        "class _PsycopgTransactionConnection:"
    )[2]
    if not transaction_adapter:
        errors.append("migration applier missing _PsycopgTransactionConnection")
    else:
        execute_body = transaction_adapter.partition("def execute(")[2].partition(
            "def fetch_all("
        )[0]
        for marker in (
            "if parameters:",
            "cursor.execute(statement, parameters)",
            "cursor.execute(statement)",
        ):
            if marker not in execute_body:
                errors.append(
                    "transaction adapter must keep parameterized and multi-statement "
                    f"execution separate; missing `{marker}`"
                )


def _validate_tests(tests_text: str, errors: list[str]) -> None:
    for version in EXPECTED_MIGRATIONS:
        if version not in tests_text:
            errors.append(f"migration tests missing committed version {version}")
    for marker in (
        "test_committed_migration_set_is_exactly_000_through_013",
        "test_rag_lifecycle_outbox_has_leased_cross_store_state_machine",
        "test_rag_tenant_deletion_fence_blocks_reingestion_tables",
        "test_audit_history_integrity_has_completion_constraints_and_exact_indexes",
        "test_audit_history_integrity_fences_exactly_once_replay_event",
        "test_audit_history_integrity_reconciles_only_exact_legacy_replay_triples",
        "test_audit_history_integrity_backfills_only_unambiguous_legacy_pairs",
        "test_audit_history_integrity_replaces_every_named_definition_on_raw_rerun",
        "test_legacy_checksums_are_backfilled_before_013_enforces_not_null",
        "test_failure_raises_migration_error_and_leaves_version_unrecorded",
        "test_applied_migration_checksum_drift_fails_closed",
        "test_applied_bootstrap_drift_is_rejected_before_changed_file_executes",
        "test_database_version_missing_from_repository_fails_closed",
        "test_legacy_null_checksums_are_backfilled_without_reapplying",
        "test_transaction_adapter_uses_parameterless_protocol_for_multistatement_sql",
        "test_lock_timeout_failure_is_sanitized_and_records_no_version",
        "test_cli_never_prints_database_exception_or_dsn",
        "pg_advisory_xact_lock",
        "transaction_count == 1",
    ):
        if marker not in tests_text:
            errors.append(f"migration tests missing `{marker}`")


def _validate_docs(docs_text: str, errors: list[str]) -> None:
    for marker in (
        "single PostgreSQL transaction",
        "transaction-scoped advisory lock",
        "SHA-256",
        "checksum drift",
        "missing from the repository",
        "legacy NULL checksums",
        "000_schema_migrations.sql",
        "007_ingestion_lease_fencing.sql",
        "008_schema_migration_checksums.sql",
        "009_drop_unsafe_ivfflat.sql",
        "010_add_retrieved_at.sql",
        "011_rag_lifecycle_outbox.sql",
        "012_rag_tenant_deletion_fence.sql",
        "013_audit_history_integrity.sql",
        "audit_runs.completion_path",
        "exactly once",
        "exactly one NULL-path run",
        "retry of an upgraded legacy request",
        "three-record atomic unit",
        "input.replay_of",
        "deterministically derived",
        "Final bidirectional",
        "verification_replay",
        "source_trace_id",
        "source_final_decision",
        "replay_final_decision",
        "decision_changed",
        "true exactly when",
        "^tr_[A-Za-z0-9_-]{8,80}$",
        "NOT VALID",
        "raw file again repairs",
        "Migration 013 rollout and locks",
        "CREATE INDEX CONCURRENTLY",
        "activeDeadlineSeconds: 900",
        "leader D",
        "lock_timeout",
        "statement_timeout",
        "14-minute",
        "postgres-migrations-check",
    ):
        if marker not in docs_text:
            errors.append(f"PostgreSQL migration docs missing `{marker}`")


def _validate_wiring(
    makefile_text: str,
    ci_workflow_text: str,
    security_workflow_text: str,
    errors: list[str],
) -> None:
    if not _makefile_phony_includes(makefile_text, GATE_TARGET):
        errors.append(f"Makefile .PHONY must include {GATE_TARGET}")
    target_body = _makefile_target_body(makefile_text, GATE_TARGET)
    if GATE_SCRIPT not in target_body:
        errors.append(f"Makefile {GATE_TARGET} must run {GATE_SCRIPT}")
    security_body = _makefile_target_body(makefile_text, "security-check")
    if GATE_SCRIPT not in security_body:
        errors.append(f"Makefile security-check must run {GATE_SCRIPT}")
    if GATE_SCRIPT not in ci_workflow_text:
        errors.append(f"CI workflow must run {GATE_SCRIPT}")
    if GATE_SCRIPT not in security_workflow_text:
        errors.append(f"security workflow must run {GATE_SCRIPT}")


def _makefile_phony_includes(makefile_text: str, target: str) -> bool:
    phony_line = next(
        (line for line in makefile_text.splitlines() if line.startswith(".PHONY:")),
        "",
    )
    return target in phony_line.split()


def _makefile_target_body(makefile_text: str, target: str) -> str:
    match = re.search(rf"(?m)^{re.escape(target)}:\s*$", makefile_text)
    if match is None:
        return ""
    body: list[str] = []
    for line in makefile_text[match.end() :].splitlines():
        if not line:
            if body:
                break
            continue
        if not line.startswith("\t"):
            break
        body.append(line)
    return "\n".join(body)


def main() -> None:
    migration_texts = load_migration_texts()
    validate_postgres_migrations(
        migration_texts=migration_texts,
        applier_text=APPLIER_PATH.read_text(encoding="utf-8"),
        tests_text=TEST_PATH.read_text(encoding="utf-8"),
        docs_text=DOC_PATH.read_text(encoding="utf-8"),
        makefile_text=MAKEFILE_PATH.read_text(encoding="utf-8"),
        ci_workflow_text=CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        security_workflow_text=SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    )
    print(
        "Validated transactional PostgreSQL migrations for "
        f"{len(migration_texts)} ordered versions."
    )


if __name__ == "__main__":
    main()
