from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self, cast

from pydantic import ValidationError

from hallu_defense.config import Settings, normalize_environment
from hallu_defense.domain.models import (
    CorpusGrant,
    CorpusGrantDisableRequest,
    CorpusGrantHistoryDiff,
    CorpusGrantHistoryDiffAction,
    CorpusGrantHistoryDiffField,
    CorpusGrantHistoryDiffRequest,
    CorpusGrantHistoryRequest,
    CorpusGrantListRequest,
    CorpusGrantUpsertRequest,
)

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CorpusGrantError(Exception):
    """Base error for corpus grant registry operations."""


class CorpusGrantConfigurationError(CorpusGrantError):
    """Raised when corpus grant storage is unsafe or unsupported."""


class CorpusGrantNotFoundError(CorpusGrantError):
    """Raised when a corpus grant mutation targets a missing grant."""


class CorpusGrantVersionConflictError(CorpusGrantError):
    """Raised when a corpus grant mutation uses a stale expected version."""


class CorpusGrantPaginationError(CorpusGrantError):
    """Raised when a corpus grant list cursor is malformed."""


class CorpusGrantStorageError(CorpusGrantError):
    """Raised when stored corpus grant state cannot be trusted."""


@dataclass(frozen=True)
class CorpusGrantListPage:
    grants: list[CorpusGrant]
    next_cursor: str | None


@dataclass(frozen=True)
class CorpusGrantDiffPage:
    diffs: list[CorpusGrantHistoryDiff]
    next_cursor: str | None


class CorpusGrantStorage(Protocol):
    def load(self) -> list[CorpusGrant]:
        ...

    def append(self, grant: CorpusGrant) -> None:
        ...


class CorpusGrantSqlConnection(Protocol):
    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        ...

    def fetch_all(self, statement: str, parameters: Sequence[object]) -> Sequence[Mapping[str, object]]:
        ...

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        ...

    def transaction(self) -> AbstractContextManager[CorpusGrantSqlConnection]:
        ...


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

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
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


class PsycopgCorpusGrantSqlConnection:
    def __init__(
        self,
        *,
        dsn: str,
        connect: PsycopgConnect | None = None,
        row_factory: object | None = None,
    ) -> None:
        if not dsn.strip():
            raise CorpusGrantConfigurationError("Postgres DSN must be configured.")
        if connect is None:
            connect, row_factory = _load_psycopg_connect()
        self._dsn = dsn
        self._connect = connect
        self._row_factory = row_factory

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        with self._connect(self._dsn, row_factory=self._row_factory) as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement, parameters)

    def fetch_all(self, statement: str, parameters: Sequence[object]) -> Sequence[Mapping[str, object]]:
        with self._connect(self._dsn, row_factory=self._row_factory) as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement, parameters)
                return cursor.fetchall()

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        return self.fetch_all(statement, parameters)

    @contextmanager
    def transaction(self) -> Iterator[CorpusGrantSqlConnection]:
        with self._connect(self._dsn, row_factory=self._row_factory) as connection:
            yield _PsycopgCorpusGrantTransaction(connection)


class _PsycopgCorpusGrantTransaction:
    def __init__(self, connection: PsycopgConnection) -> None:
        self._connection = connection

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        with self._connection.cursor() as cursor:
            cursor.execute(statement, parameters)

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        with self._connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            return cursor.fetchall()

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        return self.fetch_all(statement, parameters)

    @contextmanager
    def transaction(self) -> Iterator[CorpusGrantSqlConnection]:
        yield self


class PostgresCorpusGrantStorage:
    """Tenant-scoped append-only grant repository.

    No method loads grants for more than one tenant. Mutations are serialized per
    tenant/corpus inside the database transaction and append with
    ``ON CONFLICT DO NOTHING`` so stale interleavings become a typed conflict.
    """

    def __init__(
        self,
        *,
        table_name: str,
        connection: CorpusGrantSqlConnection,
    ) -> None:
        _validate_identifier(table_name, "corpus grants table name")
        self._table_name = table_name
        self._connection = connection

    def transaction(self) -> AbstractContextManager[CorpusGrantSqlConnection]:
        return self._connection.transaction()

    def lock_latest(
        self,
        transaction: CorpusGrantSqlConnection,
        *,
        tenant_id: str,
        corpus_id: str,
    ) -> CorpusGrant | None:
        lock_key = json.dumps([tenant_id, corpus_id], separators=(",", ":"))
        transaction.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (lock_key,),
        )
        return self.latest(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            connection=transaction,
        )

    def latest(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        connection: CorpusGrantSqlConnection | None = None,
    ) -> CorpusGrant | None:
        executor = connection or self._connection
        rows = executor.fetch_all(
            f"SELECT tenant_id, corpus_id, version, payload FROM {self._table_name} "
            "WHERE tenant_id = %s AND corpus_id = %s "
            "ORDER BY version DESC LIMIT 1",
            (tenant_id, corpus_id),
        )
        if not rows:
            return None
        if len(rows) != 1:
            raise CorpusGrantStorageError("Postgres corpus grant latest query was ambiguous.")
        return _grant_from_postgres_row(rows[0], row_label="latest grant")

    def append_if_current(
        self,
        transaction: CorpusGrantSqlConnection,
        grant: CorpusGrant,
    ) -> bool:
        statement = (
            f"INSERT INTO {self._table_name} "
            "(tenant_id, corpus_id, version, reader_roles, writer_roles, created_by, "
            "updated_by, created_at, updated_at, disabled_by, disabled_at, payload) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb) "
            "ON CONFLICT (tenant_id, corpus_id, version) DO NOTHING "
            "RETURNING tenant_id, corpus_id, version, payload"
        )
        rows = transaction.execute_returning(statement, _grant_insert_parameters(grant))
        if not rows:
            return False
        if len(rows) != 1:
            raise CorpusGrantStorageError("Postgres corpus grant insert returned multiple rows.")
        inserted = _grant_from_postgres_row(rows[0], row_label="inserted grant")
        if inserted != grant:
            raise CorpusGrantStorageError("Postgres corpus grant insert returned inconsistent state.")
        return True

    def list_current(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantListRequest,
        offset: int,
    ) -> list[CorpusGrant]:
        inner_filters = ["tenant_id = %s"]
        parameters: list[object] = [tenant_id]
        if request.corpus_id is not None:
            inner_filters.append("corpus_id = %s")
            parameters.append(request.corpus_id)
        active_filter = "" if request.include_disabled else "WHERE disabled_at IS NULL "
        statement = (
            "SELECT tenant_id, corpus_id, version, payload FROM ("
            "SELECT DISTINCT ON (corpus_id) tenant_id, corpus_id, version, updated_at, "
            f"disabled_at, payload FROM {self._table_name} "
            f"WHERE {' AND '.join(inner_filters)} "
            "ORDER BY corpus_id ASC, version DESC"
            f") AS latest {active_filter}"
            "ORDER BY corpus_id ASC, updated_at ASC OFFSET %s LIMIT %s"
        )
        parameters.extend([offset, request.limit + 1])
        return _grants_from_postgres_rows(
            self._connection.fetch_all(statement, parameters),
            row_label="current grant",
        )

    def history(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantHistoryRequest,
        offset: int,
    ) -> list[CorpusGrant]:
        filters, parameters = _postgres_history_filters(tenant_id, request)
        statement = (
            f"SELECT tenant_id, corpus_id, version, payload FROM {self._table_name} "
            f"WHERE {' AND '.join(filters)} ORDER BY sequence_id ASC OFFSET %s LIMIT %s"
        )
        parameters.extend([offset, request.limit + 1])
        return _grants_from_postgres_rows(
            self._connection.fetch_all(statement, parameters),
            row_label="history grant",
        )

    def history_with_previous(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantHistoryDiffRequest,
        offset: int,
    ) -> list[tuple[CorpusGrant | None, CorpusGrant]]:
        outer_filters, outer_parameters = _postgres_history_filters(
            tenant_id,
            request,
            include_tenant=False,
        )
        statement = (
            "WITH tenant_history AS ("
            "SELECT tenant_id, corpus_id, version, sequence_id, updated_by, updated_at, payload, "
            "LAG(payload) OVER (PARTITION BY corpus_id ORDER BY version ASC) AS previous_payload "
            f"FROM {self._table_name} WHERE tenant_id = %s"
            ") SELECT tenant_id, corpus_id, version, payload, previous_payload "
            f"FROM tenant_history WHERE {' AND '.join(outer_filters) if outer_filters else 'TRUE'} "
            "ORDER BY sequence_id ASC OFFSET %s LIMIT %s"
        )
        parameters = [tenant_id, *outer_parameters, offset, request.limit + 1]
        rows = self._connection.fetch_all(statement, parameters)
        pairs: list[tuple[CorpusGrant | None, CorpusGrant]] = []
        for row_number, row in enumerate(rows, start=1):
            grant = _grant_from_postgres_row(row, row_label=f"history diff grant {row_number}")
            previous_payload = row.get("previous_payload")
            previous = (
                None
                if previous_payload is None
                else _grant_from_payload(
                    previous_payload,
                    row_label=f"history diff previous grant {row_number}",
                )
            )
            if previous is not None and (
                previous.tenant_id != grant.tenant_id
                or previous.corpus_id != grant.corpus_id
                or previous.version + 1 != grant.version
            ):
                raise CorpusGrantStorageError(
                    "Postgres corpus grant history predecessor is inconsistent."
                )
            pairs.append((previous, grant))
        return pairs


class CorpusGrantRegistry:
    def __init__(
        self,
        storage_path: Path | None = None,
        *,
        storage: CorpusGrantStorage | None = None,
        require_expected_version: bool = False,
    ) -> None:
        if storage_path is not None and storage is not None:
            raise CorpusGrantConfigurationError(
                "Configure either storage_path or storage, not both."
            )
        self._storage_path = storage_path
        self._storage = storage
        self._require_expected_version = require_expected_version
        self._lock = threading.RLock()
        self._grants: dict[tuple[str, str], CorpusGrant] = {}
        self._history: list[CorpusGrant] = []
        if self._storage_path is not None or self._storage is not None:
            self._load_from_storage()

    def upsert(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantUpsertRequest,
        updated_by: str,
    ) -> CorpusGrant:
        now = self._now()
        key = (tenant_id, request.corpus_id)
        with self._lock:
            existing = self._grants.get(key)
            self._enforce_expected_version(
                corpus_id=request.corpus_id,
                expected_version=request.expected_version,
                existing=existing,
            )
            grant = CorpusGrant(
                tenant_id=tenant_id,
                corpus_id=request.corpus_id,
                reader_roles=request.reader_roles,
                writer_roles=request.writer_roles,
                version=(existing.version + 1) if existing is not None else 1,
                created_by=existing.created_by if existing is not None else updated_by,
                updated_by=updated_by,
                created_at=existing.created_at if existing is not None else now,
                updated_at=now,
                disabled_by=None,
                disabled_at=None,
            )
            self._append_grant_locked(grant)
            self._grants[key] = grant
            self._history.append(grant)
            return grant

    def disable(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantDisableRequest,
        disabled_by: str,
    ) -> CorpusGrant:
        now = self._now()
        key = (tenant_id, request.corpus_id)
        with self._lock:
            existing = self._grants.get(key)
            if existing is None:
                raise CorpusGrantNotFoundError(
                    f"Corpus grant not found for corpus_id={request.corpus_id!r}."
                )
            self._enforce_expected_version(
                corpus_id=request.corpus_id,
                expected_version=request.expected_version,
                existing=existing,
            )
            if existing.disabled_at is not None:
                return existing
            grant = existing.model_copy(
                update={
                    "version": existing.version + 1,
                    "updated_by": disabled_by,
                    "updated_at": now,
                    "disabled_by": disabled_by,
                    "disabled_at": now,
                }
            )
            self._append_grant_locked(grant)
            self._grants[key] = grant
            self._history.append(grant)
            return grant

    def get(self, *, tenant_id: str, corpus_id: str) -> CorpusGrant | None:
        with self._lock:
            grant = self._grants.get((tenant_id, corpus_id))
        if grant is None or grant.disabled_at is not None:
            return None
        return grant

    def list_for_tenant(self, tenant_id: str, request: CorpusGrantListRequest) -> CorpusGrantListPage:
        offset = self._cursor_offset(request.cursor)
        with self._lock:
            grants = [
                grant
                for grant in self._grants.values()
                if grant.tenant_id == tenant_id
                and (request.corpus_id is None or grant.corpus_id == request.corpus_id)
                and (request.include_disabled or grant.disabled_at is None)
            ]
        grants = sorted(grants, key=lambda grant: (grant.corpus_id, grant.updated_at))
        page = grants[offset : offset + request.limit]
        next_offset = offset + request.limit
        next_cursor = str(next_offset) if next_offset < len(grants) else None
        return CorpusGrantListPage(grants=page, next_cursor=next_cursor)

    def history_for_tenant(
        self,
        tenant_id: str,
        request: CorpusGrantHistoryRequest,
    ) -> CorpusGrantListPage:
        offset = self._cursor_offset(request.cursor)
        with self._lock:
            grants = [
                grant
                for grant in self._history
                if self._history_filter_matches(grant, tenant_id, request)
            ]
        page = grants[offset : offset + request.limit]
        next_offset = offset + request.limit
        next_cursor = str(next_offset) if next_offset < len(grants) else None
        return CorpusGrantListPage(grants=page, next_cursor=next_cursor)

    def history_diffs_for_tenant(
        self,
        tenant_id: str,
        request: CorpusGrantHistoryDiffRequest,
    ) -> CorpusGrantDiffPage:
        offset = self._cursor_offset(request.cursor)
        previous_by_key: dict[tuple[str, str], CorpusGrant] = {}
        diffs: list[CorpusGrantHistoryDiff] = []
        with self._lock:
            for grant in self._history:
                if grant.tenant_id != tenant_id:
                    continue
                key = (grant.tenant_id, grant.corpus_id)
                previous = previous_by_key.get(key)
                diff = self._diff_grant(previous, grant)
                previous_by_key[key] = grant
                if self._history_filter_matches(grant, tenant_id, request):
                    diffs.append(diff)
        page = diffs[offset : offset + request.limit]
        next_offset = offset + request.limit
        next_cursor = str(next_offset) if next_offset < len(diffs) else None
        return CorpusGrantDiffPage(diffs=page, next_cursor=next_cursor)

    def _load_from_storage(self) -> None:
        if self._storage is not None:
            stored_history = self._storage.load()
            self._history = stored_history
            self._grants = {
                (grant.tenant_id, grant.corpus_id): grant
                for grant in stored_history
            }
            return
        if self._storage_path is None or not self._storage_path.exists():
            return
        grants: dict[tuple[str, str], CorpusGrant] = {}
        history: list[CorpusGrant] = []
        with self._storage_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    stored_record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CorpusGrantStorageError(
                        f"Corpus grant record {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(stored_record, Mapping):
                    raise CorpusGrantStorageError(
                        f"Corpus grant record {line_number} must be a JSON object"
                    )
                if stored_record.get("record_type") != "corpus_grant":
                    raise CorpusGrantStorageError(
                        f"Corpus grant record {line_number} has unsupported record_type"
                    )
                payload = stored_record.get("payload")
                if not isinstance(payload, Mapping):
                    raise CorpusGrantStorageError(
                        f"Corpus grant record {line_number} payload must be an object"
                    )
                try:
                    grant = CorpusGrant.model_validate(payload)
                except ValidationError as exc:
                    raise CorpusGrantStorageError(
                        f"Corpus grant record {line_number} payload is invalid"
                    ) from exc
                history.append(grant)
                grants[(grant.tenant_id, grant.corpus_id)] = grant
        self._grants = grants
        self._history = history

    def _append_grant_locked(self, grant: CorpusGrant) -> None:
        if self._storage is not None:
            self._storage.append(grant)
            return
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        stored_record = {
            "record_type": "corpus_grant",
            "payload": grant.model_dump(mode="json"),
        }
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(stored_record, sort_keys=True, separators=(",", ":")) + "\n")

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _enforce_expected_version(
        self,
        *,
        corpus_id: str,
        expected_version: int | None,
        existing: CorpusGrant | None,
    ) -> None:
        if expected_version is None:
            if self._require_expected_version:
                raise CorpusGrantVersionConflictError(
                    "Corpus grant expected_version is required for production-like mutations."
                )
            return
        current_version = existing.version if existing is not None else 0
        if current_version != expected_version:
            raise CorpusGrantVersionConflictError(
                "Corpus grant version conflict for "
                f"corpus_id={corpus_id!r}: expected {expected_version}, current {current_version}."
            )

    def _history_filter_matches(
        self,
        grant: CorpusGrant,
        tenant_id: str,
        request: CorpusGrantHistoryRequest,
    ) -> bool:
        return (
            grant.tenant_id == tenant_id
            and (request.corpus_id is None or grant.corpus_id == request.corpus_id)
            and (request.actor_id is None or grant.updated_by == request.actor_id)
            and (request.updated_at_from is None or grant.updated_at >= request.updated_at_from)
            and (request.updated_at_to is None or grant.updated_at <= request.updated_at_to)
        )

    def _diff_grant(
        self,
        previous: CorpusGrant | None,
        grant: CorpusGrant,
    ) -> CorpusGrantHistoryDiff:
        previous_reader_roles = set(previous.reader_roles if previous is not None else [])
        previous_writer_roles = set(previous.writer_roles if previous is not None else [])
        current_reader_roles = set(grant.reader_roles)
        current_writer_roles = set(grant.writer_roles)

        reader_roles_added = sorted(current_reader_roles - previous_reader_roles)
        reader_roles_removed = sorted(previous_reader_roles - current_reader_roles)
        writer_roles_added = sorted(current_writer_roles - previous_writer_roles)
        writer_roles_removed = sorted(previous_writer_roles - current_writer_roles)

        changed_fields: list[CorpusGrantHistoryDiffField] = []
        if reader_roles_added or reader_roles_removed:
            changed_fields.append("reader_roles")
        if writer_roles_added or writer_roles_removed:
            changed_fields.append("writer_roles")
        if previous is not None and (previous.disabled_at is None) != (grant.disabled_at is None):
            changed_fields.append("disabled_state")

        action: CorpusGrantHistoryDiffAction
        if previous is None:
            action = "create"
        elif previous.disabled_at is None and grant.disabled_at is not None:
            action = "disable"
        elif previous.disabled_at is not None and grant.disabled_at is None:
            action = "reenable"
        else:
            action = "update"

        return CorpusGrantHistoryDiff(
            tenant_id=grant.tenant_id,
            corpus_id=grant.corpus_id,
            version=grant.version,
            previous_version=previous.version if previous is not None else None,
            action=action,
            changed_fields=changed_fields,
            reader_roles_added=reader_roles_added,
            reader_roles_removed=reader_roles_removed,
            writer_roles_added=writer_roles_added,
            writer_roles_removed=writer_roles_removed,
            updated_by=grant.updated_by,
            updated_at=grant.updated_at,
        )

    def _cursor_offset(self, cursor: str | None) -> int:
        if cursor is None:
            return 0
        try:
            offset = int(cursor)
        except ValueError as exc:
            raise CorpusGrantPaginationError("Corpus grant list cursor must be an integer.") from exc
        if offset < 0:
            raise CorpusGrantPaginationError("Corpus grant list cursor must be non-negative.")
        return offset


class PostgresCorpusGrantRegistry(CorpusGrantRegistry):
    """Database-authoritative registry with no process-local grant cache."""

    def __init__(
        self,
        *,
        storage: PostgresCorpusGrantStorage,
        require_expected_version: bool = False,
    ) -> None:
        super().__init__(require_expected_version=require_expected_version)
        self._postgres_storage = storage

    def upsert(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantUpsertRequest,
        updated_by: str,
    ) -> CorpusGrant:
        now = self._now()
        with self._postgres_storage.transaction() as transaction:
            existing = self._postgres_storage.lock_latest(
                transaction,
                tenant_id=tenant_id,
                corpus_id=request.corpus_id,
            )
            self._enforce_expected_version(
                corpus_id=request.corpus_id,
                expected_version=request.expected_version,
                existing=existing,
            )
            grant = CorpusGrant(
                tenant_id=tenant_id,
                corpus_id=request.corpus_id,
                reader_roles=request.reader_roles,
                writer_roles=request.writer_roles,
                version=(existing.version + 1) if existing is not None else 1,
                created_by=existing.created_by if existing is not None else updated_by,
                updated_by=updated_by,
                created_at=existing.created_at if existing is not None else now,
                updated_at=now,
                disabled_by=None,
                disabled_at=None,
            )
            if not self._postgres_storage.append_if_current(transaction, grant):
                current = self._postgres_storage.latest(
                    tenant_id=tenant_id,
                    corpus_id=request.corpus_id,
                    connection=transaction,
                )
                self._raise_version_conflict(
                    corpus_id=request.corpus_id,
                    expected_version=(existing.version if existing is not None else 0),
                    current=current,
                )
            return grant

    def disable(
        self,
        *,
        tenant_id: str,
        request: CorpusGrantDisableRequest,
        disabled_by: str,
    ) -> CorpusGrant:
        now = self._now()
        with self._postgres_storage.transaction() as transaction:
            existing = self._postgres_storage.lock_latest(
                transaction,
                tenant_id=tenant_id,
                corpus_id=request.corpus_id,
            )
            if existing is None:
                raise CorpusGrantNotFoundError(
                    f"Corpus grant not found for corpus_id={request.corpus_id!r}."
                )
            self._enforce_expected_version(
                corpus_id=request.corpus_id,
                expected_version=request.expected_version,
                existing=existing,
            )
            if existing.disabled_at is not None:
                return existing
            grant = existing.model_copy(
                update={
                    "version": existing.version + 1,
                    "updated_by": disabled_by,
                    "updated_at": now,
                    "disabled_by": disabled_by,
                    "disabled_at": now,
                }
            )
            if not self._postgres_storage.append_if_current(transaction, grant):
                current = self._postgres_storage.latest(
                    tenant_id=tenant_id,
                    corpus_id=request.corpus_id,
                    connection=transaction,
                )
                self._raise_version_conflict(
                    corpus_id=request.corpus_id,
                    expected_version=existing.version,
                    current=current,
                )
            return grant

    def get(self, *, tenant_id: str, corpus_id: str) -> CorpusGrant | None:
        grant = self._postgres_storage.latest(tenant_id=tenant_id, corpus_id=corpus_id)
        if grant is None or grant.disabled_at is not None:
            return None
        return grant

    def list_for_tenant(
        self,
        tenant_id: str,
        request: CorpusGrantListRequest,
    ) -> CorpusGrantListPage:
        offset = self._cursor_offset(request.cursor)
        grants = self._postgres_storage.list_current(
            tenant_id=tenant_id,
            request=request,
            offset=offset,
        )
        page = grants[: request.limit]
        next_cursor = str(offset + request.limit) if len(grants) > request.limit else None
        return CorpusGrantListPage(grants=page, next_cursor=next_cursor)

    def history_for_tenant(
        self,
        tenant_id: str,
        request: CorpusGrantHistoryRequest,
    ) -> CorpusGrantListPage:
        offset = self._cursor_offset(request.cursor)
        grants = self._postgres_storage.history(
            tenant_id=tenant_id,
            request=request,
            offset=offset,
        )
        page = grants[: request.limit]
        next_cursor = str(offset + request.limit) if len(grants) > request.limit else None
        return CorpusGrantListPage(grants=page, next_cursor=next_cursor)

    def history_diffs_for_tenant(
        self,
        tenant_id: str,
        request: CorpusGrantHistoryDiffRequest,
    ) -> CorpusGrantDiffPage:
        offset = self._cursor_offset(request.cursor)
        pairs = self._postgres_storage.history_with_previous(
            tenant_id=tenant_id,
            request=request,
            offset=offset,
        )
        page = pairs[: request.limit]
        next_cursor = str(offset + request.limit) if len(pairs) > request.limit else None
        return CorpusGrantDiffPage(
            diffs=[self._diff_grant(previous, grant) for previous, grant in page],
            next_cursor=next_cursor,
        )

    def _raise_version_conflict(
        self,
        *,
        corpus_id: str,
        expected_version: int,
        current: CorpusGrant | None,
    ) -> None:
        current_version = current.version if current is not None else 0
        raise CorpusGrantVersionConflictError(
            "Corpus grant version conflict for "
            f"corpus_id={corpus_id!r}: expected {expected_version}, current {current_version}."
        )


def create_corpus_grant_registry(
    settings: Settings,
    *,
    postgres_connection: CorpusGrantSqlConnection | None = None,
) -> CorpusGrantRegistry:
    backend = settings.corpus_grants_backend.strip().lower()
    environment = normalize_environment(settings.environment)
    require_expected_version = environment in {"production", "staging"}
    if require_expected_version and backend not in {"postgres", "postgresql"}:
        raise CorpusGrantConfigurationError(
            "Production and staging require the PostgreSQL persistent corpus grants backend."
        )
    if backend == "memory":
        return CorpusGrantRegistry()
    if backend == "jsonl":
        return CorpusGrantRegistry(
            storage_path=settings.corpus_grants_path,
            require_expected_version=require_expected_version,
        )
    if backend in {"postgres", "postgresql"}:
        connection = postgres_connection
        if connection is None and settings.postgres_dsn:
            connection = PsycopgCorpusGrantSqlConnection(dsn=settings.postgres_dsn)
        if connection is None:
            raise CorpusGrantConfigurationError(
                "Postgres corpus grants backend requires HALLU_DEFENSE_POSTGRES_DSN "
                "or an injected CorpusGrantSqlConnection."
            )
        return PostgresCorpusGrantRegistry(
            storage=PostgresCorpusGrantStorage(
                table_name=settings.corpus_grants_table_name,
                connection=connection,
            ),
            require_expected_version=require_expected_version,
        )
    raise CorpusGrantConfigurationError(
        f"Unsupported corpus grants backend: {settings.corpus_grants_backend}"
    )


def _grant_insert_parameters(grant: CorpusGrant) -> list[object]:
    return [
        grant.tenant_id,
        grant.corpus_id,
        grant.version,
        grant.reader_roles,
        grant.writer_roles,
        grant.created_by,
        grant.updated_by,
        grant.created_at,
        grant.updated_at,
        grant.disabled_by,
        grant.disabled_at,
        json.dumps(grant.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
    ]


def _grant_from_payload(payload: object, *, row_label: str) -> CorpusGrant:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise CorpusGrantStorageError(
                f"Postgres corpus grant {row_label} payload is not valid JSON."
            ) from exc
    if not isinstance(payload, Mapping):
        raise CorpusGrantStorageError(
            f"Postgres corpus grant {row_label} payload must be an object."
        )
    try:
        return CorpusGrant.model_validate(payload)
    except ValidationError as exc:
        raise CorpusGrantStorageError(
            f"Postgres corpus grant {row_label} payload is invalid."
        ) from exc


def _grant_from_postgres_row(
    row: Mapping[str, object],
    *,
    row_label: str,
) -> CorpusGrant:
    grant = _grant_from_payload(row.get("payload"), row_label=row_label)
    tenant_id = row.get("tenant_id")
    corpus_id = row.get("corpus_id")
    version = row.get("version")
    if (
        tenant_id != grant.tenant_id
        or corpus_id != grant.corpus_id
        or version != grant.version
        or isinstance(version, bool)
    ):
        raise CorpusGrantStorageError(
            f"Postgres corpus grant {row_label} columns do not match its payload."
        )
    return grant


def _grants_from_postgres_rows(
    rows: Sequence[Mapping[str, object]],
    *,
    row_label: str,
) -> list[CorpusGrant]:
    return [
        _grant_from_postgres_row(row, row_label=f"{row_label} {row_number}")
        for row_number, row in enumerate(rows, start=1)
    ]


def _postgres_history_filters(
    tenant_id: str,
    request: CorpusGrantHistoryRequest,
    *,
    include_tenant: bool = True,
) -> tuple[list[str], list[object]]:
    filters: list[str] = []
    parameters: list[object] = []
    if include_tenant:
        filters.append("tenant_id = %s")
        parameters.append(tenant_id)
    if request.corpus_id is not None:
        filters.append("corpus_id = %s")
        parameters.append(request.corpus_id)
    if request.actor_id is not None:
        filters.append("updated_by = %s")
        parameters.append(request.actor_id)
    if request.updated_at_from is not None:
        filters.append("updated_at >= %s")
        parameters.append(request.updated_at_from)
    if request.updated_at_to is not None:
        filters.append("updated_at <= %s")
        parameters.append(request.updated_at_to)
    return filters, parameters


def _validate_identifier(value: str, label: str) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise CorpusGrantConfigurationError(f"{label} must be a safe SQL identifier")


def _load_psycopg_connect() -> tuple[PsycopgConnect, object]:
    try:
        psycopg_module = import_module("psycopg")
        rows_module = import_module("psycopg.rows")
    except ImportError as exc:
        raise CorpusGrantConfigurationError(
            "Postgres corpus grants backend requires the psycopg package."
        ) from exc
    connect = getattr(psycopg_module, "connect")
    dict_row = getattr(rows_module, "dict_row")
    if not callable(connect):
        raise CorpusGrantConfigurationError("psycopg.connect is not callable.")
    return cast(PsycopgConnect, connect), dict_row
