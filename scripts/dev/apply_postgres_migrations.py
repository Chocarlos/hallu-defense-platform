"""Idempotent PostgreSQL migration applier for the pgvector schema.

The docker ``initdb`` mount runs ``infra/rag/pgvector/*.sql`` alphabetically, but
only once, on an empty volume. This module provides a re-runnable applier for
existing databases: it records applied files in the ``schema_migrations`` ledger
and only executes files whose filename is not yet recorded. Re-running it applies
nothing and returns an empty list.

Multi-statement decision
------------------------
Each migration file bundles several DDL statements (a ``CREATE TABLE`` plus its
indexes). Instead of splitting the file text on ``;`` -- which is fragile in the
presence of string literals or dollar-quoted bodies -- the applier hands the whole
file text to the driver in a single parameter-less ``execute`` call. psycopg (v3)
runs every statement of a parameter-less query, and with autocommit off the file
executes inside one implicit transaction, so any failure rolls the file back and
the version is never recorded. The only parameterised statement is the single
``INSERT`` that records a version after its file succeeded.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from importlib import import_module
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self, cast

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "infra" / "rag" / "pgvector"
SCHEMA_MIGRATIONS_FILENAME = "000_schema_migrations.sql"
DSN_ENV = "HALLU_DEFENSE_POSTGRES_DSN"


class MigrationError(RuntimeError):
    """Raised when a migration cannot be applied or recorded safely."""


class MigrationConnection(Protocol):
    """Structural connection used by the applier.

    Compatible by structural typing with the batch's SQL connection providers;
    this module stays independent and does not import them.
    """

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        ...

    def fetch_all(
        self, statement: str, parameters: Sequence[object] = ()
    ) -> Sequence[Mapping[str, object]]:
        ...


def apply_migrations(connection: MigrationConnection, *, migrations_dir: Path) -> list[str]:
    """Apply every not-yet-applied ``*.sql`` file in ``migrations_dir`` in order.

    Returns the list of versions (filenames) newly applied on this call. A
    re-run over an already-migrated database returns ``[]``. A failure while
    executing a file's SQL raises :class:`MigrationError` and leaves that
    version unrecorded.
    """
    schema_file = migrations_dir / SCHEMA_MIGRATIONS_FILENAME
    if not schema_file.is_file():
        raise MigrationError(
            f"Missing bootstrap migration {SCHEMA_MIGRATIONS_FILENAME} in {migrations_dir}"
        )

    # (1) Ensure the ledger table exists before we query it. The bootstrap file
    # is idempotent (CREATE TABLE IF NOT EXISTS), so running it unconditionally
    # is safe even when the table already exists.
    _execute_sql(
        connection,
        statement=schema_file.read_text(encoding="utf-8"),
        version=schema_file.name,
    )

    # (3) Load the versions already recorded as applied.
    applied = _load_applied_versions(connection)

    # (2) Discover migrations in alphabetical (filename) order: 000_, 001_, ...
    migration_files = sorted(migrations_dir.glob("*.sql"))

    newly_applied: list[str] = []
    for migration_file in migration_files:
        version = migration_file.name
        if version in applied:
            continue
        # (4) Execute the file, then record it only after the SQL succeeded.
        _execute_sql(
            connection,
            statement=migration_file.read_text(encoding="utf-8"),
            version=version,
        )
        _record_version(connection, version=version)
        newly_applied.append(version)
    # (5) Return the versions newly applied on this call.
    return newly_applied


def _load_applied_versions(connection: MigrationConnection) -> set[str]:
    rows = connection.fetch_all("SELECT version FROM schema_migrations")
    versions: set[str] = set()
    for row in rows:
        value = row.get("version")
        if isinstance(value, str):
            versions.add(value)
    return versions


def _execute_sql(connection: MigrationConnection, *, statement: str, version: str) -> None:
    try:
        connection.execute(statement)
    except MigrationError:
        raise
    except Exception as exc:
        raise MigrationError(f"Failed to apply migration {version}: {exc}") from exc


def _record_version(connection: MigrationConnection, *, version: str) -> None:
    try:
        connection.execute(
            "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
        )
    except MigrationError:
        raise
    except Exception as exc:
        raise MigrationError(
            f"Applied migration {version} but failed to record it: {exc}"
        ) from exc


class PsycopgCursor(Protocol):
    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        ...

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> object:
        ...

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        ...


class PsycopgConnection(Protocol):
    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        ...

    def cursor(self) -> PsycopgCursor:
        ...


class PsycopgConnect(Protocol):
    def __call__(self, conninfo: str, *, row_factory: object | None = None) -> PsycopgConnection:
        ...


class PsycopgMigrationConnection:
    """Adapter that satisfies :class:`MigrationConnection` over psycopg (v3).

    Each call opens its own short-lived connection (mirroring
    ``services/corpus_grants.py``); on a clean exit psycopg commits it. When no
    parameters are supplied the whole (possibly multi-statement) SQL is sent in a
    single parameter-less ``execute`` so every statement in a migration file runs.
    """

    def __init__(
        self,
        *,
        dsn: str,
        connect: PsycopgConnect | None = None,
        row_factory: object | None = None,
    ) -> None:
        if not dsn.strip():
            raise MigrationError("Postgres DSN must be configured.")
        if connect is None:
            connect, row_factory = _load_psycopg_connect()
        self._dsn = dsn
        self._connect = connect
        self._row_factory = row_factory

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        with self._connect(self._dsn, row_factory=self._row_factory) as connection:
            with connection.cursor() as cursor:
                if parameters:
                    cursor.execute(statement, parameters)
                else:
                    cursor.execute(statement)

    def fetch_all(
        self, statement: str, parameters: Sequence[object] = ()
    ) -> Sequence[Mapping[str, object]]:
        with self._connect(self._dsn, row_factory=self._row_factory) as connection:
            with connection.cursor() as cursor:
                if parameters:
                    cursor.execute(statement, parameters)
                else:
                    cursor.execute(statement)
                return cursor.fetchall()


def _load_psycopg_connect() -> tuple[PsycopgConnect, object]:
    try:
        psycopg_module = import_module("psycopg")
        rows_module = import_module("psycopg.rows")
    except ImportError as exc:
        raise MigrationError(
            "Applying Postgres migrations requires the psycopg package."
        ) from exc
    connect = getattr(psycopg_module, "connect")
    dict_row = getattr(rows_module, "dict_row")
    if not callable(connect):
        raise MigrationError("psycopg.connect is not callable.")
    return cast(PsycopgConnect, connect), dict_row


def main(argv: Sequence[str] | None = None) -> int:
    dsn = os.environ.get(DSN_ENV, "").strip()
    if not dsn:
        print(
            json.dumps(
                {"status": "error", "reason": f"{DSN_ENV} must be set"},
                separators=(",", ":"),
            )
        )
        return 1
    try:
        connection = PsycopgMigrationConnection(dsn=dsn)
        applied = apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    except MigrationError as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":")))
        return 1
    print(json.dumps({"status": "ok", "applied": applied}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
