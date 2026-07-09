"""Offline unit tests for the idempotent PostgreSQL migration applier.

These tests never touch a database. They drive
``scripts.dev.apply_postgres_migrations.apply_migrations`` through in-memory
fakes that satisfy the :class:`MigrationConnection` structural protocol, while
using the *real* ``infra/rag/pgvector/*.sql`` files on disk so the applied
version list is verified against the actual migration set and ordering.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from scripts.dev import apply_postgres_migrations as migrations

MIGRATIONS_DIR: Path = migrations.ROOT / "infra" / "rag" / "pgvector"

# The full, ordered migration set as it exists on disk (alphabetical filename
# order is also apply order; 000 is the bootstrap ledger table).
EXPECTED_ORDER: list[str] = [
    "000_schema_migrations.sql",
    "001_rag_evidence_chunks.sql",
    "002_rag_corpus_grants.sql",
    "003_audit_ledger.sql",
    "004_approval_queue.sql",
    "005_eval_reports.sql",
    "006_ingestion_outbox.sql",
]


class RecordingMigrationConnection:
    """In-memory fake satisfying ``MigrationConnection`` (no database).

    ``execute`` records every ``(statement, parameters)`` pair. When the
    statement is the ledger ``INSERT`` it also remembers the recorded version,
    so ``fetch_all`` can report the ledger contents exactly like a real
    ``SELECT version FROM schema_migrations`` would after prior inserts.
    """

    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.applied_versions: set[str] = set()

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        params: tuple[object, ...] = tuple(parameters)
        self.executed.append((statement, params))
        if statement.strip().upper().startswith("INSERT INTO SCHEMA_MIGRATIONS"):
            version: object = params[0]
            assert isinstance(version, str)
            self.applied_versions.add(version)

    def fetch_all(
        self, statement: str, parameters: Sequence[object] = ()
    ) -> Sequence[Mapping[str, object]]:
        if "schema_migrations" in statement.lower():
            rows: list[Mapping[str, object]] = [
                {"version": version} for version in sorted(self.applied_versions)
            ]
            return rows
        return []


class FailingMigrationConnection(RecordingMigrationConnection):
    """Recording fake that raises on any statement containing ``marker``.

    Used to simulate a migration failing mid-run: with ``marker="audit_runs"``
    (a table created only by ``003_audit_ledger.sql``) the 000/001/002 files
    execute and record normally, then 003 raises before it can be recorded.
    """

    def __init__(self, marker: str) -> None:
        super().__init__()
        self._marker = marker

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        if self._marker in statement:
            raise RuntimeError(f"simulated failure on statement containing {self._marker!r}")
        super().execute(statement, parameters)


def test_first_application_applies_every_migration_in_order() -> None:
    connection = RecordingMigrationConnection()

    applied: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    assert applied == EXPECTED_ORDER
    # The bootstrap ledger migration must be applied first.
    assert applied[0] == "000_schema_migrations.sql"
    # All versions end up recorded in the ledger.
    assert connection.applied_versions == set(EXPECTED_ORDER)


def test_second_run_over_same_connection_is_idempotent() -> None:
    connection = RecordingMigrationConnection()

    first: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    assert first == EXPECTED_ORDER

    second: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    assert second == []


def test_partial_state_applies_only_the_missing_migrations() -> None:
    connection = RecordingMigrationConnection()
    connection.applied_versions = {
        "000_schema_migrations.sql",
        "001_rag_evidence_chunks.sql",
        "002_rag_corpus_grants.sql",
    }

    applied: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    assert applied == [
        "003_audit_ledger.sql",
        "004_approval_queue.sql",
        "005_eval_reports.sql",
        "006_ingestion_outbox.sql",
    ]


def test_failure_raises_migration_error_and_leaves_version_unrecorded() -> None:
    connection = FailingMigrationConnection(marker="audit_runs")

    with pytest.raises(migrations.MigrationError):
        migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    # 003 failed mid-execute, so it must NOT be recorded as applied.
    assert "003_audit_ledger.sql" not in connection.applied_versions
    # The migrations that succeeded before it were recorded.
    assert "002_rag_corpus_grants.sql" in connection.applied_versions
