"""Offline unit tests for the idempotent PostgreSQL migration applier.

These tests never touch a database. They drive
``scripts.dev.apply_postgres_migrations.apply_migrations`` through in-memory
fakes that satisfy the :class:`MigrationConnection` structural protocol, while
using the *real* ``infra/rag/pgvector/*.sql`` files on disk so the applied
version list is verified against the actual migration set and ordering.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
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
    "007_ingestion_lease_fencing.sql",
    "008_schema_migration_checksums.sql",
    "009_drop_unsafe_ivfflat.sql",
    "010_add_retrieved_at.sql",
    "011_rag_lifecycle_outbox.sql",
    "012_rag_tenant_deletion_fence.sql",
    "013_audit_history_integrity.sql",
]
_NO_PARAMETERS = object()


class RecordingMigrationConnection:
    """In-memory fake satisfying ``MigrationConnection`` (no database).

    ``execute`` records every ``(statement, parameters)`` pair. When the
    statement is the ledger ``INSERT`` it also remembers the recorded version,
    so ``fetch_all`` can report the ledger contents exactly like a real
    ``SELECT version FROM schema_migrations`` would after prior inserts.
    """

    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.applied_versions: dict[str, str | None] = {}
        self.transaction_count = 0
        self.transaction_depth = 0
        self.executed_outside_transaction: list[str] = []

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        if self.transaction_depth == 0:
            self.executed_outside_transaction.append(statement)
        params: tuple[object, ...] = tuple(parameters)
        self.executed.append((statement, params))
        if statement.strip().upper().startswith("INSERT INTO SCHEMA_MIGRATIONS"):
            version: object = params[0]
            checksum: object = params[1]
            assert isinstance(version, str)
            assert isinstance(checksum, str)
            self.applied_versions[version] = checksum
        if statement.strip().upper().startswith("UPDATE SCHEMA_MIGRATIONS SET CHECKSUM_SHA256"):
            checksum, version = params
            assert isinstance(version, str)
            assert isinstance(checksum, str)
            self.applied_versions[version] = checksum

    def fetch_all(
        self, statement: str, parameters: Sequence[object] = ()
    ) -> Sequence[Mapping[str, object]]:
        if "schema_migrations" in statement.lower():
            rows: list[Mapping[str, object]] = [
                {"version": version, "checksum_sha256": self.applied_versions[version]}
                for version in sorted(self.applied_versions)
            ]
            return rows
        return []

    @contextmanager
    def transaction(self) -> Iterator[migrations.MigrationConnection]:
        before = dict(self.applied_versions)
        self.transaction_count += 1
        self.transaction_depth += 1
        try:
            yield self
        except Exception:
            self.applied_versions = before
            raise
        finally:
            self.transaction_depth -= 1


class ParameterSensitiveCursor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def __enter__(self) -> ParameterSensitiveCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(
        self,
        statement: str,
        parameters: Sequence[object] | object = _NO_PARAMETERS,
    ) -> object:
        self.calls.append((statement, parameters))
        if ";" in statement and parameters is not _NO_PARAMETERS:
            raise RuntimeError("multi-statement SQL used the parameterized protocol")
        return object()

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        return []


class ParameterSensitiveRawConnection:
    def __init__(self, cursor: ParameterSensitiveCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> ParameterSensitiveRawConnection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> ParameterSensitiveCursor:
        return self._cursor


class ParameterSensitiveConnect:
    def __init__(self) -> None:
        self.cursor = ParameterSensitiveCursor()
        self.calls = 0

    def __call__(
        self,
        _conninfo: str,
        *,
        row_factory: object | None = None,
    ) -> ParameterSensitiveRawConnection:
        del row_factory
        self.calls += 1
        return ParameterSensitiveRawConnection(self.cursor)


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
    assert set(connection.applied_versions) == set(EXPECTED_ORDER)
    assert all(connection.applied_versions.values())
    assert connection.transaction_count == 1
    assert connection.executed_outside_transaction == []
    assert connection.executed[:3] == [
        (migrations.MIGRATION_LOCK_TIMEOUT_SQL, ()),
        (migrations.MIGRATION_STATEMENT_TIMEOUT_SQL, ()),
        ("SELECT pg_advisory_xact_lock(%s)", (migrations.MIGRATION_LOCK_KEY,)),
    ]
    for version, checksum in connection.applied_versions.items():
        expected = migrations._migration_checksum(
            (MIGRATIONS_DIR / version).read_text(encoding="utf-8")
        )
        assert checksum == expected
        assert len(expected) == 64
        assert set(expected) <= set("0123456789abcdef")


def test_committed_migration_set_is_exactly_000_through_013() -> None:
    versions = [path.name for path in sorted(MIGRATIONS_DIR.glob("*.sql"))]

    assert versions == EXPECTED_ORDER
    assert len(versions) == 14


def test_second_run_over_same_connection_is_idempotent() -> None:
    connection = RecordingMigrationConnection()

    first: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    assert first == EXPECTED_ORDER

    second: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    assert second == []


def test_partial_state_applies_only_the_missing_migrations() -> None:
    connection = RecordingMigrationConnection()
    connection.applied_versions = {
        version: migrations._migration_checksum((MIGRATIONS_DIR / version).read_text(encoding="utf-8"))
        for version in EXPECTED_ORDER[:3]
    }

    applied: list[str] = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    assert applied == [
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
    ]


def test_final_migration_removes_approximate_vector_index_without_mutating_table() -> None:
    sql = (MIGRATIONS_DIR / "009_drop_unsafe_ivfflat.sql").read_text(encoding="utf-8")

    assert "DROP INDEX IF EXISTS idx_rag_evidence_chunks_embedding" in sql
    assert "DROP TABLE" not in sql.upper()
    assert "USING ivfflat" not in sql
    assert "USING hnsw" not in sql


def test_retrieved_at_migration_backfills_before_enforcing_not_null() -> None:
    sql = (MIGRATIONS_DIR / "010_add_retrieved_at.sql").read_text(encoding="utf-8")

    add_position = sql.index("ADD COLUMN IF NOT EXISTS retrieved_at TIMESTAMPTZ")
    backfill_position = sql.index("SET retrieved_at = created_at")
    not_null_position = sql.index("ALTER COLUMN retrieved_at SET NOT NULL")
    assert add_position < backfill_position < not_null_position
    assert "DROP TABLE" not in sql.upper()


def test_rag_lifecycle_outbox_has_leased_cross_store_state_machine() -> None:
    sql = (MIGRATIONS_DIR / "011_rag_lifecycle_outbox.sql").read_text(encoding="utf-8")

    assert "CREATE TABLE IF NOT EXISTS rag_lifecycle_operations" in sql
    assert "operation_id text PRIMARY KEY" in sql
    assert "'pending', 'processing', 'external_deleted', 'completed'" in sql
    assert "lease_token text" in sql
    assert "external_deleted_count bigint NOT NULL DEFAULT 0" in sql
    assert "target_tenant_id text" in sql
    assert "evidence_cutoff timestamptz" in sql


def test_rag_tenant_deletion_fence_blocks_reingestion_tables() -> None:
    sql = (MIGRATIONS_DIR / "012_rag_tenant_deletion_fence.sql").read_text(
        encoding="utf-8"
    )

    assert "CREATE TABLE IF NOT EXISTS rag_tenant_deletion_tombstones" in sql
    assert "operation_id text NOT NULL REFERENCES rag_lifecycle_operations" in sql
    assert "WHERE tenant_id = NEW.tenant_id" in sql
    assert "BEFORE INSERT OR UPDATE ON rag_evidence_chunks" in sql
    assert "BEFORE INSERT OR UPDATE ON rag_ingestion_jobs" in sql
    assert "ERRCODE = '42501'" in sql
    assert "DROP TABLE" not in sql.upper()


def test_audit_history_integrity_has_unique_and_keyset_indexes() -> None:
    sql = (MIGRATIONS_DIR / "013_audit_history_integrity.sql").read_text(
        encoding="utf-8"
    )

    assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_tenant_event_id" in sql
    assert "ON audit_events (tenant_id, event_id)" in sql
    assert "ix_audit_events_tenant_type_created_event" in sql
    assert "ix_audit_events_tenant_type_trace_created_event" in sql
    assert "(payload ->> 'event_type')" in sql
    assert "created_at DESC" in sql
    assert "event_id DESC" in sql
    assert "DROP" not in sql.upper()


def test_lock_timeout_failure_is_sanitized_and_records_no_version() -> None:
    sentinel = "postgresql://user:super-secret@postgres/db SELECT private_payload"

    class TimeoutConnection(RecordingMigrationConnection):
        def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
            if statement == migrations.MIGRATION_LOCK_TIMEOUT_SQL:
                raise TimeoutError(sentinel)
            super().execute(statement, parameters)

    timeout_connection = TimeoutConnection()
    with pytest.raises(migrations.MigrationError) as exc_info:
        migrations.apply_migrations(timeout_connection, migrations_dir=MIGRATIONS_DIR)

    assert sentinel not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert timeout_connection.applied_versions == {}
    assert timeout_connection.transaction_count == 1


def test_cli_never_prints_database_exception_or_dsn(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sentinel_dsn = "postgresql://user:cli-secret@postgres/private"

    class TimeoutConnection(RecordingMigrationConnection):
        def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
            if statement == migrations.MIGRATION_LOCK_TIMEOUT_SQL:
                raise TimeoutError(f"timeout for {sentinel_dsn} with private SQL")
            super().execute(statement, parameters)

    monkeypatch.setenv(migrations.DSN_ENV, sentinel_dsn)
    monkeypatch.setattr(
        migrations,
        "PsycopgMigrationConnection",
        lambda **_kwargs: TimeoutConnection(),
    )

    assert migrations.main([]) == 1
    output = capsys.readouterr().out
    assert "cli-secret" not in output
    assert "private SQL" not in output
    assert "PostgreSQL migration transaction failed" in output


def test_cli_rejects_production_migration_dsn_without_verify_full(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(migrations.ENVIRONMENT_ENV, "production")
    monkeypatch.setenv(
        migrations.DSN_ENV,
        "postgresql://migration-user:private@db.example.test/app?sslmode=require",
    )
    monkeypatch.delenv(migrations.DSN_FILE_ENV, raising=False)
    monkeypatch.setenv(
        migrations.POSTGRES_CA_CERT_PATH_ENV,
        str((Path.cwd() / "missing-postgres-ca.crt").resolve()),
    )

    assert migrations.main([]) == 1
    output = capsys.readouterr().out
    assert "sslmode=verify-full" in output
    assert "private" not in output


def test_failure_raises_migration_error_and_leaves_version_unrecorded() -> None:
    connection = FailingMigrationConnection(marker="audit_runs")

    with pytest.raises(migrations.MigrationError):
        migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    # The entire batch, including earlier versions, rolls back atomically.
    assert connection.applied_versions == {}


def test_applied_migration_checksum_drift_fails_closed() -> None:
    connection = RecordingMigrationConnection()
    migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    connection.applied_versions["003_audit_ledger.sql"] = "0" * 64

    with pytest.raises(migrations.MigrationError, match="checksum"):
        migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)


def test_applied_bootstrap_drift_is_rejected_before_changed_file_executes(
    tmp_path: Path,
) -> None:
    migration_dir = tmp_path / "migrations"
    migration_dir.mkdir()
    for source in sorted(MIGRATIONS_DIR.glob("*.sql")):
        (migration_dir / source.name).write_text(
            source.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    bootstrap = migration_dir / migrations.SCHEMA_MIGRATIONS_FILENAME
    bootstrap.write_text(
        bootstrap.read_text(encoding="utf-8") + "\nSELECT 'DRIFT_SENTINEL';\n",
        encoding="utf-8",
    )
    connection = RecordingMigrationConnection()
    connection.applied_versions = {
        version: migrations._migration_checksum(
            (MIGRATIONS_DIR / version).read_text(encoding="utf-8")
        )
        for version in EXPECTED_ORDER
    }

    with pytest.raises(migrations.MigrationError, match="checksum"):
        migrations.apply_migrations(connection, migrations_dir=migration_dir)

    assert all("DRIFT_SENTINEL" not in statement for statement, _ in connection.executed)


def test_database_version_missing_from_repository_fails_closed() -> None:
    connection = RecordingMigrationConnection()
    connection.applied_versions = {"999_removed_migration.sql": "0" * 64}

    with pytest.raises(migrations.MigrationError, match="missing from the repository"):
        migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    assert connection.applied_versions == {"999_removed_migration.sql": "0" * 64}


def test_legacy_null_checksums_are_backfilled_without_reapplying() -> None:
    connection = RecordingMigrationConnection()
    connection.applied_versions = dict.fromkeys(EXPECTED_ORDER)

    applied = migrations.apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)

    assert applied == []
    assert all(connection.applied_versions.values())


def test_transaction_adapter_uses_parameterless_protocol_for_multistatement_sql() -> None:
    connect = ParameterSensitiveConnect()
    connection = migrations.PsycopgMigrationConnection(
        dsn="postgresql://test",
        connect=connect,
        row_factory=object(),
    )

    with connection.transaction() as transaction:
        transaction.execute("SELECT 1; SELECT 2;")
        transaction.execute("SELECT %s", (1,))

    assert connect.calls == 1
    assert connect.cursor.calls[0] == ("SELECT 1; SELECT 2;", _NO_PARAMETERS)
    assert connect.cursor.calls[1] == ("SELECT %s", (1,))
