from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from importlib import import_module
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self, cast

if TYPE_CHECKING:
    from hallu_defense.config import Settings

DEFAULT_POOL_MIN_SIZE = 1
DEFAULT_POOL_MAX_SIZE = 8
DEFAULT_POOL_TIMEOUT_SECONDS = 10.0


class PostgresProviderError(RuntimeError):
    """Raised when the PostgreSQL provider cannot satisfy a request.

    Driver-level failures are always wrapped in this error so callers only
    depend on this module's exception type, never on psycopg internals.
    """


class SqlConnectionProvider(Protocol):
    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        ...

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        ...

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        ...

    def transaction(self) -> AbstractContextManager[SqlConnectionProvider]:
        ...


class PostgresCursor(Protocol):
    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        ...

    def execute(self, statement: str, parameters: Sequence[object]) -> object:
        ...

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        ...


class PostgresConnection(Protocol):
    def cursor(self) -> PostgresCursor:
        ...


class PostgresConnectionContext(Protocol):
    def __enter__(self) -> PostgresConnection:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        ...


class PostgresConnectionPool(Protocol):
    def connection(self) -> PostgresConnectionContext:
        ...

    def close(self) -> None:
        ...


class PostgresPoolFactory(Protocol):
    def __call__(
        self,
        conninfo: str,
        *,
        min_size: int,
        max_size: int,
        timeout: float,
        kwargs: Mapping[str, object] | None = None,
    ) -> PostgresConnectionPool:
        ...


class PooledPostgresProvider:
    """SqlConnectionProvider backed by a lazily created psycopg_pool pool.

    The pool (and therefore the psycopg-pool import) is only constructed on the
    first query, mirroring the lazy-import pattern used by corpus_grants and
    rag_index. Tests inject a fake pool via ``pool=`` so the module works with
    psycopg-pool absent from the environment.
    """

    def __init__(
        self,
        *,
        dsn: str,
        min_size: int = DEFAULT_POOL_MIN_SIZE,
        max_size: int = DEFAULT_POOL_MAX_SIZE,
        timeout_seconds: float = DEFAULT_POOL_TIMEOUT_SECONDS,
        pool: object | None = None,
    ) -> None:
        if not dsn.strip():
            raise PostgresProviderError("Postgres DSN must be configured.")
        if min_size < 1:
            raise PostgresProviderError("Postgres pool min_size must be at least 1.")
        if max_size < min_size:
            raise PostgresProviderError("Postgres pool max_size must be >= min_size.")
        if timeout_seconds <= 0:
            raise PostgresProviderError("Postgres pool timeout_seconds must be positive.")
        self._dsn = dsn
        self._min_size = min_size
        self._max_size = max_size
        self._timeout_seconds = timeout_seconds
        self._pool_lock = threading.Lock()
        self._pool: PostgresConnectionPool | None = (
            cast(PostgresConnectionPool, pool) if pool is not None else None
        )

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        pool = self._ensure_pool()
        try:
            with pool.connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(statement, parameters)
        except Exception as exc:
            raise PostgresProviderError("PostgreSQL execute failed.") from exc
        return None

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        pool = self._ensure_pool()
        try:
            with pool.connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(statement, parameters)
                    return list(cursor.fetchall())
        except Exception as exc:
            raise PostgresProviderError("PostgreSQL fetch_all failed.") from exc

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        pool = self._ensure_pool()
        try:
            with pool.connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(statement, parameters)
                    return list(cursor.fetchall())
        except Exception as exc:
            raise PostgresProviderError("PostgreSQL execute_returning failed.") from exc

    @contextmanager
    def transaction(self) -> Iterator[SqlConnectionProvider]:
        pool = self._ensure_pool()
        body_error: BaseException | None = None
        try:
            with pool.connection() as connection:
                try:
                    yield _TransactionSqlProvider(connection)
                except BaseException as exc:
                    body_error = exc
                    raise
        except Exception as exc:
            if body_error is exc:
                raise
            raise PostgresProviderError("PostgreSQL transaction failed.") from exc

    def _ensure_pool(self) -> PostgresConnectionPool:
        pool = self._pool
        if pool is not None:
            return pool
        with self._pool_lock:
            if self._pool is None:
                factory, dict_row = _load_pool_factory()
                try:
                    self._pool = factory(
                        self._dsn,
                        min_size=self._min_size,
                        max_size=self._max_size,
                        timeout=self._timeout_seconds,
                        kwargs={"row_factory": dict_row},
                    )
                except Exception as exc:
                    raise PostgresProviderError(
                        "Failed to open the PostgreSQL connection pool."
                    ) from exc
            return self._pool

    def close(self) -> None:
        """Close the lazily-created pool so short-lived tools leave no sessions."""
        with self._pool_lock:
            pool = self._pool
            self._pool = None
        if pool is None:
            return
        try:
            pool.close()
        except Exception as exc:
            raise PostgresProviderError("Failed to close the PostgreSQL connection pool.") from exc


class RecordingSqlProvider:
    """In-memory SqlConnectionProvider for tests.

    Records every call as ``(method, statement, tuple(parameters))`` and returns
    caller-configured canonical rows so downstream writers can assert exact SQL
    and simulate 0-row (403/409) vs 1-row outcomes without a database.
    """

    def __init__(
        self,
        *,
        fetch_all_rows: Sequence[Mapping[str, object]] = (),
        returning_rows: Sequence[Mapping[str, object]] = (),
    ) -> None:
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self._fetch_all_rows: list[Mapping[str, object]] = list(fetch_all_rows)
        self._returning_rows: list[Mapping[str, object]] = list(returning_rows)

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        self.calls.append(("execute", statement, tuple(parameters)))
        return None

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(("fetch_all", statement, tuple(parameters)))
        return list(self._fetch_all_rows)

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self.calls.append(("execute_returning", statement, tuple(parameters)))
        return list(self._returning_rows)

    @contextmanager
    def transaction(self) -> Iterator[SqlConnectionProvider]:
        yield self


class _TransactionSqlProvider:
    """SQL provider bound to one pool connection and its commit/rollback scope."""

    def __init__(self, connection: PostgresConnection) -> None:
        self._connection = connection

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(statement, parameters)
        except Exception as exc:
            raise PostgresProviderError("PostgreSQL transaction execute failed.") from exc

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(statement, parameters)
                return list(cursor.fetchall())
        except Exception as exc:
            raise PostgresProviderError("PostgreSQL transaction fetch_all failed.") from exc

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        try:
            with self._connection.cursor() as cursor:
                cursor.execute(statement, parameters)
                return list(cursor.fetchall())
        except Exception as exc:
            raise PostgresProviderError(
                "PostgreSQL transaction execute_returning failed."
            ) from exc

    @contextmanager
    def transaction(self) -> Iterator[SqlConnectionProvider]:
        yield self


def build_postgres_provider(settings: Settings) -> PooledPostgresProvider:
    dsn = settings.postgres_dsn
    if dsn is None or not dsn.strip():
        raise PostgresProviderError(
            "PostgreSQL provider requires HALLU_DEFENSE_POSTGRES_DSN to be configured."
        )
    # Pool sizing lives on Settings fields added by the integration writer. They
    # are read by exact name with the provider defaults as a graceful fallback so
    # this module type-checks before the integrator extends config.Settings.
    min_size = int(getattr(settings, "postgres_pool_min_size", DEFAULT_POOL_MIN_SIZE))
    max_size = int(getattr(settings, "postgres_pool_max_size", DEFAULT_POOL_MAX_SIZE))
    timeout_seconds = float(
        getattr(settings, "postgres_pool_timeout_seconds", DEFAULT_POOL_TIMEOUT_SECONDS)
    )
    return PooledPostgresProvider(
        dsn=dsn,
        min_size=min_size,
        max_size=max_size,
        timeout_seconds=timeout_seconds,
    )


def _load_pool_factory() -> tuple[PostgresPoolFactory, object]:
    try:
        pool_module = import_module("psycopg_pool")
        rows_module = import_module("psycopg.rows")
    except ImportError as exc:
        raise PostgresProviderError(
            "PooledPostgresProvider requires the psycopg-pool and psycopg packages."
        ) from exc
    connection_pool = getattr(pool_module, "ConnectionPool", None)
    dict_row = getattr(rows_module, "dict_row", None)
    if not callable(connection_pool):
        raise PostgresProviderError("psycopg_pool.ConnectionPool is not callable.")
    if dict_row is None:
        raise PostgresProviderError("psycopg.rows.dict_row is unavailable.")
    return cast(PostgresPoolFactory, connection_pool), dict_row
