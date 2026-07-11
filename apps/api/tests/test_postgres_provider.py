from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Mapping, Sequence
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

import hallu_defense.services.postgres as postgres
from hallu_defense.services.postgres import (
    PooledPostgresProvider,
    PostgresProviderError,
    RecordingSqlProvider,
    build_postgres_provider,
)

if TYPE_CHECKING:
    from hallu_defense.config import Settings


class FakeCursor:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]],
        execute_error: Exception | None,
    ) -> None:
        self.execute_calls: list[tuple[str, Sequence[object]]] = []
        self._rows = list(rows)
        self._execute_error = execute_error

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        return None

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        self.execute_calls.append((statement, parameters))
        if self._execute_error is not None:
            raise self._execute_error

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        return self._rows


class FakeConnection:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]],
        execute_error: Exception | None,
    ) -> None:
        self.cursor_instance = FakeCursor(rows, execute_error)

    def cursor(self) -> FakeCursor:
        return self.cursor_instance


class FakeConnectionContext:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]],
        execute_error: Exception | None,
    ) -> None:
        self.connection = FakeConnection(rows, execute_error)
        self.committed = False
        self.rolled_back = False

    def __enter__(self) -> FakeConnection:
        return self.connection

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        if exc_type is None:
            self.committed = True
        else:
            self.rolled_back = True
        return None


class FakePool:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]] = (),
        execute_error: Exception | None = None,
    ) -> None:
        self.contexts: list[FakeConnectionContext] = []
        self._rows = list(rows)
        self._execute_error = execute_error
        self.closed = False

    def connection(self) -> FakeConnectionContext:
        context = FakeConnectionContext(self._rows, self._execute_error)
        self.contexts.append(context)
        return context

    def close(self) -> None:
        self.closed = True


class RecordingPoolFactory:
    def __init__(self, pool: FakePool) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self._pool = pool

    def __call__(
        self,
        conninfo: str,
        *,
        min_size: int,
        max_size: int,
        timeout: float,
        kwargs: Mapping[str, object] | None = None,
    ) -> FakePool:
        self.calls.append(
            (
                conninfo,
                {
                    "min_size": min_size,
                    "max_size": max_size,
                    "timeout": timeout,
                    "kwargs": dict(kwargs or {}),
                },
            )
        )
        return self._pool


def test_execute_runs_statement_and_commits_on_clean_exit() -> None:
    pool = FakePool()
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    provider.execute("INSERT INTO t (a) VALUES (%s)", ["value"])

    context = pool.contexts[-1]
    assert context.connection.cursor_instance.execute_calls == [
        ("INSERT INTO t (a) VALUES (%s)", ["value"])
    ]
    assert context.committed is True
    assert context.rolled_back is False


def test_execute_defaults_to_empty_parameters() -> None:
    pool = FakePool()
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    provider.execute("SELECT 1")

    assert pool.contexts[-1].connection.cursor_instance.execute_calls == [("SELECT 1", ())]


def test_close_releases_initialized_pool_and_is_idempotent() -> None:
    pool = FakePool()
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    provider.close()
    provider.close()

    assert pool.closed is True


def test_fetch_all_returns_fake_rows_as_list_of_dicts() -> None:
    rows = [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]
    pool = FakePool(rows=rows)
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    result = provider.fetch_all("SELECT id, name FROM t WHERE a = %s", ["value"])

    assert result == rows
    assert isinstance(result, list)
    context = pool.contexts[-1]
    assert context.connection.cursor_instance.execute_calls == [
        ("SELECT id, name FROM t WHERE a = %s", ["value"])
    ]
    assert context.committed is True


def test_execute_returning_returns_returning_rows_in_committed_transaction() -> None:
    rows = [{"id": 42, "version": 1}]
    pool = FakePool(rows=rows)
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    result = provider.execute_returning(
        "INSERT INTO t (a) VALUES (%s) RETURNING id, version",
        ["value"],
    )

    assert result == rows
    context = pool.contexts[-1]
    assert context.connection.cursor_instance.execute_calls == [
        ("INSERT INTO t (a) VALUES (%s) RETURNING id, version", ["value"])
    ]
    assert context.committed is True


def test_transaction_reuses_one_connection_and_commits_all_operations() -> None:
    rows = [{"affected_count": 2}]
    pool = FakePool(rows=rows)
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    with provider.transaction() as transaction:
        transaction.execute("DELETE FROM first WHERE tenant_id = %s", ["tenant-a"])
        returned = transaction.execute_returning(
            "DELETE FROM second WHERE tenant_id = %s RETURNING affected_count",
            ["tenant-a"],
        )

    assert returned == rows
    assert len(pool.contexts) == 1
    context = pool.contexts[0]
    assert context.connection.cursor_instance.execute_calls == [
        ("DELETE FROM first WHERE tenant_id = %s", ["tenant-a"]),
        (
            "DELETE FROM second WHERE tenant_id = %s RETURNING affected_count",
            ["tenant-a"],
        ),
    ]
    assert context.committed is True
    assert context.rolled_back is False


def test_transaction_rolls_back_all_operations_when_body_fails() -> None:
    pool = FakePool()
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    with pytest.raises(ValueError, match="audit append failed"):
        with provider.transaction() as transaction:
            transaction.execute("DELETE FROM first", ())
            raise ValueError("audit append failed")

    context = pool.contexts[0]
    assert context.committed is False
    assert context.rolled_back is True


def test_driver_error_is_wrapped_in_provider_error_and_rolls_back() -> None:
    pool = FakePool(execute_error=RuntimeError("connection reset by peer"))
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    with pytest.raises(PostgresProviderError, match="execute failed"):
        provider.execute("INSERT INTO t (a) VALUES (%s)", ["value"])

    context = pool.contexts[-1]
    assert context.committed is False
    assert context.rolled_back is True


def test_fetch_all_driver_error_is_wrapped() -> None:
    pool = FakePool(execute_error=RuntimeError("boom"))
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)

    with pytest.raises(PostgresProviderError, match="fetch_all failed"):
        provider.fetch_all("SELECT 1")


def test_pooled_provider_rejects_blank_dsn() -> None:
    with pytest.raises(PostgresProviderError, match="DSN"):
        PooledPostgresProvider(dsn="   ")


def test_pooled_provider_rejects_invalid_pool_sizing() -> None:
    with pytest.raises(PostgresProviderError, match="min_size"):
        PooledPostgresProvider(dsn="postgresql://localhost/db", min_size=0)
    with pytest.raises(PostgresProviderError, match="max_size"):
        PooledPostgresProvider(dsn="postgresql://localhost/db", min_size=4, max_size=2)
    with pytest.raises(PostgresProviderError, match="timeout_seconds"):
        PooledPostgresProvider(dsn="postgresql://localhost/db", timeout_seconds=0.0)


def test_lazy_pool_is_built_once_with_configured_sizing_and_dict_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FakePool()
    factory = RecordingPoolFactory(pool)
    sentinel_dict_row = object()
    monkeypatch.setattr(
        postgres,
        "_load_pool_factory",
        lambda: (factory, sentinel_dict_row),
    )
    provider = PooledPostgresProvider(
        dsn="postgresql://localhost/db",
        min_size=2,
        max_size=5,
        timeout_seconds=7.5,
    )

    provider.execute("INSERT INTO t (a) VALUES (%s)", ["one"])
    provider.execute("INSERT INTO t (a) VALUES (%s)", ["two"])

    assert len(factory.calls) == 1
    conninfo, kwargs = factory.calls[0]
    assert conninfo == "postgresql://localhost/db"
    assert kwargs == {
        "min_size": 2,
        "max_size": 5,
        "timeout": 7.5,
        "kwargs": {"row_factory": sentinel_dict_row},
    }


def test_lazy_pool_construction_failure_is_wrapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom() -> tuple[postgres.PostgresPoolFactory, object]:
        raise postgres.PostgresProviderError(
            "PooledPostgresProvider requires the psycopg-pool and psycopg packages."
        )

    monkeypatch.setattr(postgres, "_load_pool_factory", _boom)
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db")

    with pytest.raises(PostgresProviderError, match="psycopg-pool"):
        provider.execute("SELECT 1")


def test_recording_sql_provider_records_calls_and_returns_canonical_rows() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[{"id": 1}],
        returning_rows=[{"id": 2, "version": 1}],
    )

    provider.execute("DELETE FROM t WHERE id = %s", [1])
    assert provider.fetch_all("SELECT * FROM t WHERE x = %s", ["a"]) == [{"id": 1}]
    assert provider.execute_returning(
        "INSERT INTO t (a) VALUES (%s) RETURNING id, version",
        ["b"],
    ) == [{"id": 2, "version": 1}]
    assert provider.calls == [
        ("execute", "DELETE FROM t WHERE id = %s", (1,)),
        ("fetch_all", "SELECT * FROM t WHERE x = %s", ("a",)),
        ("execute_returning", "INSERT INTO t (a) VALUES (%s) RETURNING id, version", ("b",)),
    ]


def test_recording_sql_provider_defaults_to_zero_rows() -> None:
    provider = RecordingSqlProvider()

    assert provider.fetch_all("SELECT 1") == []
    assert provider.execute_returning("INSERT INTO t DEFAULT VALUES RETURNING id") == []


def test_build_postgres_provider_fails_closed_without_dsn() -> None:
    settings = SimpleNamespace(
        postgres_dsn=None,
        postgres_pool_min_size=1,
        postgres_pool_max_size=8,
        postgres_pool_timeout_seconds=10.0,
    )

    with pytest.raises(PostgresProviderError, match="POSTGRES_DSN"):
        build_postgres_provider(cast("Settings", settings))


def test_build_postgres_provider_fails_closed_on_blank_dsn() -> None:
    settings = SimpleNamespace(
        postgres_dsn="   ",
        postgres_pool_min_size=1,
        postgres_pool_max_size=8,
        postgres_pool_timeout_seconds=10.0,
    )

    with pytest.raises(PostgresProviderError, match="POSTGRES_DSN"):
        build_postgres_provider(cast("Settings", settings))


def test_build_postgres_provider_wires_settings_pool_sizing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = FakePool()
    factory = RecordingPoolFactory(pool)
    sentinel_dict_row = object()
    monkeypatch.setattr(
        postgres,
        "_load_pool_factory",
        lambda: (factory, sentinel_dict_row),
    )
    settings = SimpleNamespace(
        postgres_dsn="postgresql://localhost/hallu_defense",
        postgres_pool_min_size=3,
        postgres_pool_max_size=9,
        postgres_pool_timeout_seconds=4.5,
    )

    provider = build_postgres_provider(cast("Settings", settings))
    provider.execute("SELECT 1")

    conninfo, kwargs = factory.calls[0]
    assert conninfo == "postgresql://localhost/hallu_defense"
    assert kwargs["min_size"] == 3
    assert kwargs["max_size"] == 9
    assert kwargs["timeout"] == 4.5


def test_module_import_does_not_require_psycopg_pool() -> None:
    # The module is imported at collection time in an environment where
    # psycopg-pool is not installed; the lazy import guarantees this works.
    module = importlib.import_module("hallu_defense.services.postgres")
    assert hasattr(module, "PooledPostgresProvider")

    pool = FakePool()
    provider = module.PooledPostgresProvider(dsn="postgresql://localhost/db", pool=pool)
    provider.execute("SELECT 1")
    assert pool.contexts[-1].committed is True


def test_lazy_path_requires_psycopg_pool_when_absent() -> None:
    if importlib.util.find_spec("psycopg_pool") is not None:
        pytest.skip("psycopg-pool is installed; lazy import would succeed")
    provider = PooledPostgresProvider(dsn="postgresql://localhost/db")

    with pytest.raises(PostgresProviderError, match="psycopg-pool"):
        provider.execute("SELECT 1")
