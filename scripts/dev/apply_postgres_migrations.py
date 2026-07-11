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

import hashlib
import json
import os
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from importlib import import_module
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self, cast

from hallu_defense.runtime_secrets import RuntimeSecretError, load_runtime_secret
from hallu_defense.postgres_tls import (
    PostgresTlsConfigurationError,
    validate_postgres_tls,
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = ROOT / "infra" / "rag" / "pgvector"
SCHEMA_MIGRATIONS_FILENAME = "000_schema_migrations.sql"
DSN_ENV = "HALLU_DEFENSE_POSTGRES_DSN"
DSN_FILE_ENV = "HALLU_DEFENSE_POSTGRES_DSN_FILE"
ENVIRONMENT_ENV = "HALLU_DEFENSE_ENV"
POSTGRES_CA_CERT_PATH_ENV = "HALLU_DEFENSE_POSTGRES_CA_CERT_PATH"
KIND_INSECURE_TLS_ENV = "HALLU_DEFENSE_POSTGRES_KIND_INSECURE_TLS_ENABLED"
MIGRATION_LOCK_KEY = 4_820_743_254_460_609_101
MIGRATION_LOCK_TIMEOUT_SQL = "SET LOCAL lock_timeout = '30s'"
MIGRATION_STATEMENT_TIMEOUT_SQL = "SET LOCAL statement_timeout = '14min'"
BOOTSTRAP_LEDGER_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    checksum_sha256 text,
    applied_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE schema_migrations
    ADD COLUMN IF NOT EXISTS checksum_sha256 text;
"""


class MigrationError(RuntimeError):
    """Raised when a migration cannot be applied or recorded safely."""


class MigrationConnection(Protocol):
    """Structural connection used by the applier.

    Compatible by structural typing with the batch's SQL connection providers;
    this module stays independent and does not import them.
    """

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None: ...

    def fetch_all(
        self, statement: str, parameters: Sequence[object] = ()
    ) -> Sequence[Mapping[str, object]]: ...

    def transaction(self) -> AbstractContextManager[MigrationConnection]: ...


def apply_migrations(
    connection: MigrationConnection, *, migrations_dir: Path
) -> list[str]:
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

    migration_files = sorted(migrations_dir.glob("*.sql"))
    newly_applied: list[str] = []
    with _sanitized_transaction(connection) as transaction:
        # Bound both advisory/table lock waits and total DDL execution below
        # the deployment migration Job's 15-minute deadline.
        transaction.execute(MIGRATION_LOCK_TIMEOUT_SQL)
        transaction.execute(MIGRATION_STATEMENT_TIMEOUT_SQL)
        # A transaction-scoped advisory lock serializes independent migration
        # runners without leaving a lock behind after success or rollback.
        transaction.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK_KEY,))

        # Bootstrap from a runner-owned invariant, not from migration 000. An
        # already-applied 000 must have its checksum verified before any bytes
        # from that file are executed; otherwise drift detection would happen
        # after the potentially changed SQL had already run.
        _execute_sql(
            transaction,
            statement=BOOTSTRAP_LEDGER_SQL,
            version="internal schema_migrations bootstrap",
        )

        applied = _load_applied_versions(transaction)
        file_versions = {migration_file.name for migration_file in migration_files}
        unknown_versions = sorted(set(applied) - file_versions)
        if unknown_versions:
            raise MigrationError(
                "Database records migration versions missing from the repository "
                f"(count={len(unknown_versions)})."
            )

        for migration_file in migration_files:
            version = migration_file.name
            statement = migration_file.read_text(encoding="utf-8")
            checksum = _migration_checksum(statement)
            if version in applied:
                recorded_checksum = applied[version]
                if recorded_checksum is None:
                    _record_legacy_checksum(
                        transaction, version=version, checksum=checksum
                    )
                    continue
                if recorded_checksum != checksum:
                    raise MigrationError(
                        f"Applied migration {version} checksum does not match the repository."
                    )
                continue
            _execute_sql(transaction, statement=statement, version=version)
            _record_version(transaction, version=version, checksum=checksum)
            newly_applied.append(version)
    return newly_applied


def _load_applied_versions(connection: MigrationConnection) -> dict[str, str | None]:
    try:
        rows = connection.fetch_all(
            "SELECT version, checksum_sha256 FROM schema_migrations"
        )
    except Exception as exc:
        raise MigrationError(
            f"Failed to read the migration ledger ({_safe_exception_type(exc)})."
        ) from None
    versions: dict[str, str | None] = {}
    for row in rows:
        value = row.get("version")
        if isinstance(value, str):
            checksum = row.get("checksum_sha256")
            versions[value] = (
                checksum if isinstance(checksum, str) and checksum else None
            )
    return versions


@contextmanager
def _sanitized_transaction(
    connection: MigrationConnection,
) -> Iterator[MigrationConnection]:
    try:
        with connection.transaction() as transaction:
            yield transaction
    except MigrationError:
        raise
    except Exception as exc:
        error_type = _safe_exception_type(exc)
        raise MigrationError(
            f"PostgreSQL migration transaction failed ({error_type})."
        ) from None


def _execute_sql(
    connection: MigrationConnection, *, statement: str, version: str
) -> None:
    try:
        connection.execute(statement)
    except Exception as exc:
        raise MigrationError(
            f"Failed to apply migration {version} ({_safe_exception_type(exc)})."
        ) from None


def _record_version(
    connection: MigrationConnection,
    *,
    version: str,
    checksum: str,
) -> None:
    try:
        connection.execute(
            "INSERT INTO schema_migrations (version, checksum_sha256) VALUES (%s, %s)",
            (version, checksum),
        )
    except Exception as exc:
        raise MigrationError(
            f"Applied migration {version} but failed to record it "
            f"({_safe_exception_type(exc)})."
        ) from None


def _record_legacy_checksum(
    connection: MigrationConnection,
    *,
    version: str,
    checksum: str,
) -> None:
    try:
        connection.execute(
            "UPDATE schema_migrations SET checksum_sha256 = %s "
            "WHERE version = %s AND checksum_sha256 IS NULL",
            (checksum, version),
        )
    except Exception as exc:
        raise MigrationError(
            f"Failed to backfill migration checksum for {version} "
            f"({_safe_exception_type(exc)})."
        ) from None


def _migration_checksum(statement: str) -> str:
    return hashlib.sha256(statement.encode("utf-8")).hexdigest()


def _safe_exception_type(exc: Exception) -> str:
    name = type(exc).__name__
    if 1 <= len(name) <= 64 and name.replace("_", "a").isalnum():
        return name
    return "DatabaseError"


class PsycopgCursor(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> object: ...

    def fetchall(self) -> Sequence[Mapping[str, object]]: ...


class PsycopgConnection(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def cursor(self) -> PsycopgCursor: ...


class PsycopgConnect(Protocol):
    def __call__(
        self, conninfo: str, *, row_factory: object | None = None
    ) -> PsycopgConnection: ...


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

    @contextmanager
    def transaction(self) -> Iterator[MigrationConnection]:
        with self._connect(self._dsn, row_factory=self._row_factory) as connection:
            yield _PsycopgTransactionConnection(connection)


class _PsycopgTransactionConnection:
    def __init__(self, connection: PsycopgConnection) -> None:
        self._connection = connection

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        with self._connection.cursor() as cursor:
            if parameters:
                cursor.execute(statement, parameters)
            else:
                # psycopg must use the parameter-less/simple-query path for the
                # multi-statement migration files.
                cursor.execute(statement)

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        with self._connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            return cursor.fetchall()

    @contextmanager
    def transaction(self) -> Iterator[MigrationConnection]:
        yield self


def _load_psycopg_connect() -> tuple[PsycopgConnect, object]:
    try:
        psycopg_module = import_module("psycopg")
        rows_module = import_module("psycopg.rows")
    except ImportError:
        raise MigrationError(
            "Applying Postgres migrations requires the psycopg package."
        ) from None
    connect = getattr(psycopg_module, "connect")
    dict_row = getattr(rows_module, "dict_row")
    if not callable(connect):
        raise MigrationError("psycopg.connect is not callable.")
    return cast(PsycopgConnect, connect), dict_row


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        dsn = load_runtime_secret(
            os.environ,
            value_variable=DSN_ENV,
            file_variable=DSN_FILE_ENV,
        )
    except RuntimeSecretError as exc:
        print(
            json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":"))
        )
        return 1
    if not dsn:
        print(
            json.dumps(
                {
                    "status": "error",
                    "reason": f"{DSN_ENV} or {DSN_FILE_ENV} must be set",
                },
                separators=(",", ":"),
            )
        )
        return 1
    try:
        validate_postgres_tls(
            dsn,
            environment=os.getenv(ENVIRONMENT_ENV, "local"),
            ca_cert_path=(
                Path(os.environ[POSTGRES_CA_CERT_PATH_ENV])
                if os.getenv(POSTGRES_CA_CERT_PATH_ENV)
                else None
            ),
            kind_insecure_tls_enabled=_strict_environment_bool(KIND_INSECURE_TLS_ENV),
        )
        connection = PsycopgMigrationConnection(dsn=dsn)
        applied = apply_migrations(connection, migrations_dir=MIGRATIONS_DIR)
    except (MigrationError, PostgresTlsConfigurationError) as exc:
        print(
            json.dumps({"status": "error", "reason": str(exc)}, separators=(",", ":"))
        )
        return 1
    print(json.dumps({"status": "ok", "applied": applied}, separators=(",", ":")))
    return 0


def _strict_environment_bool(name: str) -> bool:
    raw = os.getenv(name, "false").strip().lower()
    if raw not in {"true", "false"}:
        raise PostgresTlsConfigurationError(f"{name} must be true or false.")
    return raw == "true"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
