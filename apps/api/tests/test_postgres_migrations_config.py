from __future__ import annotations

from pathlib import Path
from typing import TypedDict

import pytest

from scripts.ci import check_postgres_migrations as gate


class _MigrationGateInputs(TypedDict):
    migration_texts: dict[str, str]
    applier_text: str
    tests_text: str
    docs_text: str
    makefile_text: str
    ci_workflow_text: str
    security_workflow_text: str


def _inputs() -> _MigrationGateInputs:
    return {
        "migration_texts": gate.load_migration_texts(),
        "applier_text": gate.APPLIER_PATH.read_text(encoding="utf-8"),
        "tests_text": gate.TEST_PATH.read_text(encoding="utf-8"),
        "docs_text": gate.DOC_PATH.read_text(encoding="utf-8"),
        "makefile_text": gate.MAKEFILE_PATH.read_text(encoding="utf-8"),
        "ci_workflow_text": gate.CI_WORKFLOW_PATH.read_text(encoding="utf-8"),
        "security_workflow_text": gate.SECURITY_WORKFLOW_PATH.read_text(encoding="utf-8"),
    }


def _validate(inputs: _MigrationGateInputs) -> None:
    gate.validate_postgres_migrations(
        migration_texts=inputs["migration_texts"],
        applier_text=inputs["applier_text"],
        tests_text=inputs["tests_text"],
        docs_text=inputs["docs_text"],
        makefile_text=inputs["makefile_text"],
        ci_workflow_text=inputs["ci_workflow_text"],
        security_workflow_text=inputs["security_workflow_text"],
    )


def test_postgres_migrations_gate_validates_current_repository() -> None:
    _validate(_inputs())


def test_postgres_migrations_gate_requires_exact_fourteen_versions() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts.pop("013_audit_history_integrity.sql")
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match="exactly 000 through 013"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_audit_history_integrity() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["013_audit_history_integrity.sql"] = "SELECT 1;"
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match="audit_events"):
        _validate(inputs)


@pytest.mark.parametrize(
    ("marker", "replacement", "error_match"),
    [
        ("ADD COLUMN IF NOT EXISTS completion_path text", "SELECT 1", "completion_path"),
        (
            "DO $audit_replay_backfill$",
            "DO $unsafe_replay_upgrade$",
            "audit_replay_backfill",
        ),
        (
            "DO $audit_history_backfill$",
            "DO $unsafe_legacy_upgrade$",
            "audit_history_backfill",
        ),
        (
            "SET completion_path = completion.completion_path",
            "SET completion_path = NULL",
            "SET completion_path",
        ),
        (
            "payload #>> '{input,replay_of}' = replay_row.source_trace_id",
            "payload #>> '{input,replay_of}' <> replay_row.source_trace_id",
            "replay_of",
        ),
        (
            "ALTER COLUMN checksum_sha256 SET NOT NULL",
            "ALTER COLUMN checksum_sha256 DROP NOT NULL",
            "checksum_sha256 SET NOT NULL",
        ),
        (
            "CREATE UNIQUE INDEX ux_audit_runs_tenant_trace_completion_path",
            "CREATE INDEX ux_audit_runs_tenant_trace_completion_path",
            "CREATE UNIQUE INDEX ux_audit_runs",
        ),
        (
            "WHERE completion_path IS NOT NULL",
            "WHERE completion_path IS NULL",
            "completion_path IS NOT NULL",
        ),
        (
            'payload @> \'{"method":"POST","status_code":200,"outcome":"success"}\'::jsonb',
            'payload @> \'{"method":"GET","status_code":200,"outcome":"success"}\'::jsonb',
            "method",
        ),
        (
            "ADD CONSTRAINT ck_audit_events_verification_replay",
            "ADD CONSTRAINT ck_audit_events_unfenced_replay",
            "verification_replay",
        ),
        (
            "(payload #>> '{metadata,source_trace_id}')",
            "(payload #>> '{metadata,unbounded_source_trace_id}')",
            "source_trace_id",
        ),
        (
            "'^tr_[A-Za-z0-9_-]{8,80}$'",
            "'^tr_[A-Za-z0-9_-]+$'",
            "8,80",
        ),
        (
            "payload #>> '{metadata,replay_final_decision}' IN (",
            "payload #>> '{metadata,replay_final_decision}' NOT IN (",
            "replay_final_decision.*IN",
        ),
        (
            "<> (payload #>> '{metadata,replay_final_decision}')",
            "= (payload #>> '{metadata,replay_final_decision}')",
            "source_final_decision.*<>",
        ),
        (
            "CREATE UNIQUE INDEX ux_audit_events_tenant_trace_replay_path",
            "CREATE INDEX ux_audit_events_tenant_trace_replay_path",
            "CREATE UNIQUE INDEX ux_audit_events_tenant_trace_replay_path",
        ),
        (
            "DROP INDEX IF EXISTS ux_audit_events_tenant_event_id",
            "SELECT 1",
            "DROP INDEX",
        ),
    ],
)
def test_postgres_migrations_gate_requires_exact_audit_integrity_contract(
    marker: str,
    replacement: str,
    error_match: str,
) -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["013_audit_history_integrity.sql"] = migration_texts[
        "013_audit_history_integrity.sql"
    ].replace(marker, replacement)
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match=error_match):
        _validate(inputs)


def test_postgres_migrations_gate_rejects_noncorrecting_or_destructive_013() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["013_audit_history_integrity.sql"] = (
        migration_texts["013_audit_history_integrity.sql"].replace(
            "CREATE UNIQUE INDEX ux_audit_events_tenant_event_id",
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_tenant_event_id",
        )
        + "\nDELETE FROM audit_events;\n"
    )
    inputs["migration_texts"] = migration_texts

    with pytest.raises(
        gate.PostgresMigrationsConfigError,
        match="repairs drifted definitions|preserve audit data",
    ):
        _validate(inputs)


def test_postgres_migrations_gate_requires_tenant_deletion_fence() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["012_rag_tenant_deletion_fence.sql"] = "SELECT 1;"
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match="tombstones"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_ivfflat_removal() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["009_drop_unsafe_ivfflat.sql"] = "SELECT 1;"
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match="DROP INDEX"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_persisted_retrieval_time() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["010_add_retrieved_at.sql"] = "SELECT 1;"
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match="retrieved_at"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_checksum_ledger_column() -> None:
    inputs = _inputs()
    migration_texts = dict(inputs["migration_texts"])
    migration_texts["008_schema_migration_checksums.sql"] = migration_texts[
        "008_schema_migration_checksums.sql"
    ].replace("checksum_sha256 text", "legacy_checksum text")
    inputs["migration_texts"] = migration_texts

    with pytest.raises(gate.PostgresMigrationsConfigError, match="checksum_sha256"):
        _validate(inputs)


@pytest.mark.parametrize(
    ("marker", "replacement", "error_match"),
    [
        ("SELECT pg_advisory_xact_lock(%s)", "SELECT 1", "advisory_xact_lock"),
        (
            "with connection.transaction() as transaction:",
            "transaction = connection",
            "connection.transaction",
        ),
        (
            'hashlib.sha256(statement.encode("utf-8")).hexdigest()',
            'hashlib.md5(statement.encode("utf-8")).hexdigest()',
            "sha256",
        ),
        ("recorded_checksum != checksum", "False", "recorded_checksum"),
        (
            "Database records migration versions missing from the repository",
            "Database migration mismatch",
            "missing from the repository",
        ),
    ],
)
def test_postgres_migrations_gate_requires_integrity_markers(
    marker: str,
    replacement: str,
    error_match: str,
) -> None:
    inputs = _inputs()
    inputs["applier_text"] = str(inputs["applier_text"]).replace(marker, replacement)

    with pytest.raises(gate.PostgresMigrationsConfigError, match=error_match):
        _validate(inputs)


def test_postgres_migrations_gate_requires_parameterless_multistatement_path() -> None:
    inputs = _inputs()
    applier = str(inputs["applier_text"])
    transaction_start = applier.index("class _PsycopgTransactionConnection:")
    prefix = applier[:transaction_start]
    adapter = applier[transaction_start:].replace(
        "cursor.execute(statement)\n",
        "cursor.execute(statement, ())\n",
        1,
    )
    inputs["applier_text"] = prefix + adapter

    with pytest.raises(gate.PostgresMigrationsConfigError, match="multi-statement"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_behavior_tests() -> None:
    inputs = _inputs()
    inputs["tests_text"] = str(inputs["tests_text"]).replace(
        "test_database_version_missing_from_repository_fails_closed",
        "missing_behavior_test",
    )

    with pytest.raises(gate.PostgresMigrationsConfigError, match="database_version_missing"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_transaction_docs() -> None:
    inputs = _inputs()
    inputs["docs_text"] = str(inputs["docs_text"]).replace(
        "transaction-scoped advisory lock",
        "database lock",
    )

    with pytest.raises(gate.PostgresMigrationsConfigError, match="advisory lock"):
        _validate(inputs)


def test_postgres_migrations_gate_requires_ci_wiring() -> None:
    inputs = _inputs()
    inputs["ci_workflow_text"] = str(inputs["ci_workflow_text"]).replace(
        gate.GATE_SCRIPT,
        "scripts/ci/missing_migration_gate.py",
    )

    with pytest.raises(gate.PostgresMigrationsConfigError, match="CI workflow"):
        _validate(inputs)


def test_migration_paths_are_repository_files() -> None:
    for version in gate.EXPECTED_MIGRATIONS:
        assert (gate.MIGRATIONS_DIR / Path(version)).is_file()
