from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Protocol, TypeVar
from uuid import uuid4

from pydantic import ValidationError

from hallu_defense.config import Settings, normalize_environment
from hallu_defense.domain.models import AuditEvent, FinalDecision, VerificationRun
from hallu_defense.services.postgres import SqlConnectionProvider

SENSITIVE_KEYWORDS = (
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
REDACTED = "[REDACTED]"
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
    re.compile(r"(?i)([?&](?:sig|signature|token|access_token|x-amz-signature)=)[^&#\s]+"),
)

# Default upper bound on records returned by export()/export_events() across all
# backends. The real Settings field ``audit_export_max_records`` is added by the
# integration writer; ``create_audit_ledger`` reads it with getattr so this module
# type-checks and behaves identically before that field lands.
DEFAULT_EXPORT_MAX_RECORDS = 1000

# Postgres schema is frozen by the migrations. Table/column names are literal
# constants (never derived from user input), so the statements are safe to build
# without runtime identifier validation.
AUDIT_RUNS_TABLE = "audit_runs"
AUDIT_EVENTS_TABLE = "audit_events"
_INSERT_RUN_SQL = (
    "INSERT INTO audit_runs (tenant_id, trace_id, payload, created_at) "
    "VALUES (%s, %s, %s::jsonb, %s)"
)
_INSERT_EVENT_SQL = (
    "INSERT INTO audit_events (tenant_id, trace_id, event_id, payload, created_at) "
    "VALUES (%s, %s, %s, %s::jsonb, %s)"
)
_INSERT_COMPLETED_RUN_SQL = (
    "INSERT INTO audit_runs (tenant_id, trace_id, completion_path, payload, created_at) "
    "VALUES (%s, %s, %s, %s::jsonb, %s) ON CONFLICT DO NOTHING "
    "RETURNING id, tenant_id, trace_id, completion_path, created_at, payload"
)
_INSERT_COMPLETED_EVENT_SQL = (
    "INSERT INTO audit_events (tenant_id, trace_id, event_id, payload, created_at) "
    "VALUES (%s, %s, %s, %s::jsonb, %s) ON CONFLICT DO NOTHING "
    "RETURNING id, tenant_id, trace_id, event_id, created_at, payload"
)
_SELECT_COMPLETED_RUN_SQL = (
    "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
    "FROM audit_runs WHERE tenant_id = %s AND trace_id = %s AND completion_path = %s "
    "ORDER BY id DESC LIMIT 2 FOR SHARE"
)
_SELECT_COMPLETED_EVENT_SQL = (
    "SELECT id, tenant_id, trace_id, event_id, created_at, payload FROM audit_events "
    "WHERE tenant_id = %s AND trace_id = %s "
    "AND payload ->> 'event_type' = %s AND payload ->> 'path' = %s "
    "ORDER BY id DESC LIMIT 2 FOR SHARE"
)
_SELECT_REPLAY_SOURCE_RUNS_SQL = (
    "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
    "FROM audit_runs WHERE tenant_id = %s AND trace_id = %s "
    "AND payload #>> '{input,replay_of}' IS NULL "
    "ORDER BY created_at DESC, id DESC LIMIT 2"
)
_EXPORT_SNAPSHOT_TRANSACTION_SQL = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
VERIFICATION_COMPLETED_EVENT = "verification_completed"
VERIFICATION_REPLAY_EVENT = "verification_replay"
VERIFICATION_REPLAY_PATH = "/verification/replay"
AUDIT_EVENT_ID_RE = re.compile(r"^evt_[A-Za-z0-9_-]+$")
AUDIT_TRACE_ID_RE = re.compile(r"^tr_[A-Za-z0-9_-]{8,80}$")
VERIFICATION_COMPLETION_PATHS = frozenset(
    {
        "/verification/run",
        "/v2/verification/run",
        "/verification/replay",
    }
)

_RecordT = TypeVar("_RecordT")


class AuditLedgerError(RuntimeError):
    pass


class AuditLedgerConfigurationError(AuditLedgerError):
    pass


class AuditLedgerStorageError(AuditLedgerError):
    pass


class ReplaySourceConflictError(AuditLedgerError):
    pass


@dataclass(frozen=True)
class CompletedVerificationRecord:
    """The canonical completion unit committed by the persistence boundary."""

    run: VerificationRun
    event: AuditEvent
    related_events: tuple[AuditEvent, ...] = ()


@dataclass(frozen=True)
class AuditLedgerSnapshot:
    """A bounded run/event view observed at one storage snapshot."""

    runs: tuple[VerificationRun, ...]
    events: tuple[AuditEvent, ...]


@dataclass(frozen=True)
class _LoadedRun:
    run: VerificationRun
    completion_path: str | None


class AuditLedgerStorage(Protocol):
    """Persistence seam for the audit ledger.

    Implementations receive verification runs and audit events that have already
    been redacted by :class:`AuditLedger`; they must never re-derive or log the
    original payloads. ``load_*`` returns at most ``limit`` of the most recent
    records for the requested tenant/trace filter, in chronological order.
    """

    def append_run(self, run: VerificationRun) -> None: ...

    def append_event(self, event: AuditEvent) -> None: ...

    def append_run_with_event(
        self,
        *,
        run: VerificationRun,
        event: AuditEvent,
        related_events: Sequence[AuditEvent] = (),
    ) -> CompletedVerificationRecord: ...

    def load_runs(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[VerificationRun]: ...

    def load_events(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[AuditEvent]: ...

    def load_snapshot(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
        include_events: bool,
    ) -> AuditLedgerSnapshot:
        """Return bounded runs/events from one coherent storage snapshot."""

        ...

    def load_replay_source_candidates(
        self,
        *,
        tenant_id: str,
        trace_id: str,
    ) -> list[VerificationRun]:
        """Return at most two non-replay runs without applying the export cap first."""

        ...

    def load_event_page(
        self,
        *,
        tenant_id: str,
        event_type: str,
        trace_id: str | None,
        before_created_at: datetime | None,
        before_event_id: str | None,
        limit: int,
    ) -> list[AuditEvent]:
        """Return a newest-first keyset page filtered in persistent storage."""

        ...


class PostgresAuditLedgerStorage:
    """AuditLedgerStorage backed by the shared SqlConnectionProvider seam.

    Runs and events are written as already-redacted JSONB payloads. Reads are
    indexed on (tenant_id, created_at)/(tenant_id, trace_id) and bounded by the
    export cap via ``ORDER BY created_at DESC, id DESC LIMIT %s`` (the bigserial
    id is a deterministic tiebreaker for equal timestamps); the most recent N
    rows are then returned in chronological (ascending) order so postgres
    exports match the memory/jsonl backends.
    """

    def __init__(self, *, connection: SqlConnectionProvider) -> None:
        self._connection = connection

    def append_run(self, run: VerificationRun) -> None:
        self._insert_run(self._connection, run)

    def append_event(self, event: AuditEvent) -> None:
        self._insert_event(self._connection, event)

    def append_run_with_event(
        self,
        *,
        run: VerificationRun,
        event: AuditEvent,
        related_events: Sequence[AuditEvent] = (),
    ) -> CompletedVerificationRecord:
        with self._connection.transaction() as transaction:
            inserted_runs = transaction.execute_returning(
                _INSERT_COMPLETED_RUN_SQL,
                [
                    run.tenant_id,
                    run.trace_id,
                    event.path,
                    _dump_payload(run),
                    run.created_at,
                ],
            )
            expected_events = (event, *related_events)
            inserted_event_rows = [
                transaction.execute_returning(
                    _INSERT_COMPLETED_EVENT_SQL,
                    [
                        candidate.tenant_id,
                        candidate.trace_id,
                        candidate.event_id,
                        _dump_payload(candidate),
                        candidate.created_at,
                    ],
                )
                for candidate in expected_events
            ]
            if len(inserted_runs) > 1 or any(len(rows) > 1 for rows in inserted_event_rows):
                raise AuditLedgerStorageError(
                    "Postgres audit completion insert returned multiple rows"
                )
            insertion_states = [bool(inserted_runs), *map(bool, inserted_event_rows)]
            if any(state != insertion_states[0] for state in insertion_states[1:]):
                raise AuditLedgerStorageError(
                    "Postgres audit completion found a partial persisted pair or unit"
                )
            if inserted_runs:
                self._validate_export_rows(inserted_runs, limit=1)
                for rows in inserted_event_rows:
                    self._validate_export_rows(rows, limit=1)
                persisted_run = self._completed_run_from_row(
                    inserted_runs[0],
                    1,
                    path=event.path,
                )
                persisted_events = tuple(
                    self._event_from_row(rows[0], index)
                    for index, rows in enumerate(inserted_event_rows, start=1)
                )
            else:
                run_rows = transaction.fetch_all(
                    _SELECT_COMPLETED_RUN_SQL,
                    [run.tenant_id, run.trace_id, event.path],
                )
                persisted_event_rows = [
                    transaction.fetch_all(
                        _SELECT_COMPLETED_EVENT_SQL,
                        [
                            run.tenant_id,
                            run.trace_id,
                            candidate.event_type,
                            candidate.path,
                        ],
                    )
                    for candidate in expected_events
                ]
                if len(run_rows) != 1 or any(len(rows) != 1 for rows in persisted_event_rows):
                    raise AuditLedgerStorageError(
                        "Postgres audit completion retry found an incomplete or duplicate unit"
                    )
                self._validate_export_rows(run_rows, limit=1)
                for rows in persisted_event_rows:
                    self._validate_export_rows(rows, limit=1)
                persisted_run = self._completed_run_from_row(
                    run_rows[0],
                    1,
                    path=event.path,
                )
                persisted_events = tuple(
                    self._event_from_row(rows[0], index)
                    for index, rows in enumerate(persisted_event_rows, start=1)
                )
            return _validate_completed_pair(
                persisted_run=persisted_run,
                persisted_event=persisted_events[0],
                persisted_related_events=persisted_events[1:],
                expected_run=run,
                expected_event=event,
                expected_related_events=related_events,
            )

    def _insert_run(
        self,
        connection: SqlConnectionProvider,
        run: VerificationRun,
    ) -> None:
        connection.execute(
            _INSERT_RUN_SQL,
            [run.tenant_id, run.trace_id, _dump_payload(run), run.created_at],
        )

    def _insert_event(
        self,
        connection: SqlConnectionProvider,
        event: AuditEvent,
    ) -> None:
        connection.execute(
            _INSERT_EVENT_SQL,
            [
                event.tenant_id,
                event.trace_id,
                event.event_id,
                _dump_payload(event),
                event.created_at,
            ],
        )

    def load_runs(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[VerificationRun]:
        loaded_runs = self._load_run_records(
            self._connection,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limit,
        )
        return [loaded.run for loaded in loaded_runs]

    def load_events(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[AuditEvent]:
        return self._load_events(
            self._connection,
            tenant_id=tenant_id,
            trace_id=trace_id,
            limit=limit,
        )

    def load_snapshot(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
        include_events: bool,
    ) -> AuditLedgerSnapshot:
        with self._connection.transaction() as transaction:
            transaction.execute(_EXPORT_SNAPSHOT_TRANSACTION_SQL)
            loaded_runs = self._load_run_records(
                transaction,
                tenant_id=tenant_id,
                trace_id=trace_id,
                limit=limit + 1,
            )
            events = (
                self._load_events(
                    transaction,
                    tenant_id=tenant_id,
                    trace_id=trace_id,
                    limit=limit + 1,
                )
                if include_events
                else []
            )
            runs_truncated = len(loaded_runs) > limit
            events_truncated = len(events) > limit
            loaded_runs = _apply_export_cap(loaded_runs, limit)
            events = _apply_export_cap(events, limit)
            self._validate_snapshot_integrity(
                loaded_runs,
                events,
                include_events=include_events,
                runs_truncated=runs_truncated,
                events_truncated=events_truncated,
            )
        return AuditLedgerSnapshot(
            runs=tuple(loaded.run for loaded in loaded_runs),
            events=tuple(events),
        )

    def load_replay_source_candidates(
        self,
        *,
        tenant_id: str,
        trace_id: str,
    ) -> list[VerificationRun]:
        rows = self._connection.fetch_all(
            _SELECT_REPLAY_SOURCE_RUNS_SQL,
            [tenant_id, trace_id],
        )
        self._validate_export_rows(rows, limit=2)
        candidates: list[VerificationRun] = []
        for row_number, row in enumerate(rows, start=1):
            loaded = self._loaded_run_from_row(row, row_number)
            self._validate_requested_scope(
                loaded.run,
                tenant_id=tenant_id,
                trace_id=trace_id,
                row_number=row_number,
            )
            if loaded.run.input.get("replay_of") is not None:
                raise AuditLedgerStorageError(
                    "Postgres replay source query returned a replayed verification run"
                )
            candidates.append(loaded.run)
        return candidates

    def _load_run_records(
        self,
        connection: SqlConnectionProvider,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[_LoadedRun]:
        statement, parameters = self._select_statement(
            AUDIT_RUNS_TABLE, tenant_id=tenant_id, trace_id=trace_id, limit=limit
        )
        rows = connection.fetch_all(statement, parameters)
        self._validate_export_rows(rows, limit=limit)
        loaded_runs: list[_LoadedRun] = []
        for row_number, row in enumerate(rows, start=1):
            loaded = self._loaded_run_from_row(row, row_number)
            self._validate_requested_scope(
                loaded.run,
                tenant_id=tenant_id,
                trace_id=trace_id,
                row_number=row_number,
            )
            loaded_runs.append(loaded)
        loaded_runs.reverse()
        return loaded_runs

    def _load_events(
        self,
        connection: SqlConnectionProvider,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[AuditEvent]:
        statement, parameters = self._select_statement(
            AUDIT_EVENTS_TABLE, tenant_id=tenant_id, trace_id=trace_id, limit=limit
        )
        rows = connection.fetch_all(statement, parameters)
        self._validate_export_rows(rows, limit=limit)
        events: list[AuditEvent] = []
        event_identities: set[tuple[str, str]] = set()
        for row_number, row in enumerate(rows, start=1):
            event = self._event_from_row(row, row_number)
            if event.event_type == VERIFICATION_COMPLETED_EVENT:
                _validate_completion_event_contract(event)
            elif event.event_type == VERIFICATION_REPLAY_EVENT:
                _validate_replay_event_contract(event)
            self._validate_requested_scope(
                event,
                tenant_id=tenant_id,
                trace_id=trace_id,
                row_number=row_number,
            )
            event_identity = event.tenant_id, event.event_id
            if event_identity in event_identities:
                raise AuditLedgerStorageError(
                    "Postgres audit ledger export contains a duplicate tenant event ID"
                )
            event_identities.add(event_identity)
            events.append(event)
        events.reverse()
        return events

    def load_event_page(
        self,
        *,
        tenant_id: str,
        event_type: str,
        trace_id: str | None,
        before_created_at: datetime | None,
        before_event_id: str | None,
        limit: int,
    ) -> list[AuditEvent]:
        conditions = ["tenant_id = %s", "payload ->> 'event_type' = %s"]
        parameters: list[object] = [tenant_id, event_type]
        if trace_id is not None:
            conditions.append("trace_id = %s")
            parameters.append(trace_id)
        if before_created_at is not None and before_event_id is not None:
            conditions.append("(created_at, event_id) < (%s, %s)")
            parameters.extend([before_created_at, before_event_id])
        parameters.append(limit)
        statement = (
            "SELECT id, tenant_id, trace_id, event_id, created_at, payload "
            "FROM audit_events WHERE "
            + " AND ".join(conditions)
            + " ORDER BY created_at DESC, event_id DESC LIMIT %s"
        )
        rows = self._connection.fetch_all(statement, parameters)
        if len(rows) > limit:
            raise AuditLedgerStorageError(
                "Postgres audit ledger event page exceeded its requested limit"
            )
        events: list[AuditEvent] = []
        previous_key: tuple[datetime, str] | None = None
        seen_row_ids: set[int] = set()
        seen_event_ids: set[str] = set()
        for row_number, row in enumerate(rows, start=1):
            row_id = row.get("id")
            if (
                not isinstance(row_id, int)
                or isinstance(row_id, bool)
                or row_id < 1
                or row_id in seen_row_ids
            ):
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} has an invalid or duplicate "
                    "database row ID"
                )
            seen_row_ids.add(row_id)
            event = self._event_from_row(row, row_number)
            if event.event_id in seen_event_ids:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} has a duplicate tenant event ID"
                )
            seen_event_ids.add(event.event_id)
            if (
                event.tenant_id != tenant_id
                or event.event_type != event_type
                or (trace_id is not None and event.trace_id != trace_id)
            ):
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} violates page filters"
                )
            if event_type == VERIFICATION_COMPLETED_EVENT:
                _validate_completion_event_contract(event)
            elif event_type == VERIFICATION_REPLAY_EVENT:
                _validate_replay_event_contract(event)
            if event.created_at.tzinfo is None:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} timestamp lacks timezone"
                )
            event_key = event.created_at, event.event_id
            if (
                before_created_at is not None
                and before_event_id is not None
                and event_key >= (before_created_at, before_event_id)
            ):
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} violates page cursor"
                )
            if previous_key is not None and event_key >= previous_key:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} violates page ordering"
                )
            previous_key = event_key
            events.append(event)
        return events

    def _validate_snapshot_integrity(
        self,
        loaded_runs: Sequence[_LoadedRun],
        events: Sequence[AuditEvent],
        *,
        include_events: bool,
        runs_truncated: bool,
        events_truncated: bool,
    ) -> None:
        run_groups: dict[tuple[str, str, str], list[VerificationRun]] = {}
        completion_groups: dict[tuple[str, str, str], list[AuditEvent]] = {}
        replay_groups: dict[tuple[str, str, str], list[AuditEvent]] = {}
        for loaded in loaded_runs:
            if loaded.completion_path is None:
                continue
            key = (
                loaded.run.tenant_id,
                loaded.run.trace_id,
                loaded.completion_path,
            )
            run_groups.setdefault(key, []).append(loaded.run)
        for event in events:
            key = event.tenant_id, event.trace_id, event.path
            if event.event_type == VERIFICATION_COMPLETED_EVENT:
                completion_groups.setdefault(key, []).append(event)
            elif event.event_type == VERIFICATION_REPLAY_EVENT:
                replay_groups.setdefault(key, []).append(event)

        if any(len(group) != 1 for group in run_groups.values()) or any(
            len(group) != 1 for group in completion_groups.values()
        ):
            raise AuditLedgerStorageError(
                "Postgres audit export snapshot contains a duplicate completion unit"
            )
        if any(len(group) != 1 for group in replay_groups.values()):
            raise AuditLedgerStorageError(
                "Postgres audit export snapshot contains duplicate replay provenance"
            )

        # A cap+1 lookahead proves whether either bounded collection was truncated.
        # When neither was, every completed run must have the exact path-matched
        # completion (and replay provenance). Otherwise validate intersections
        # without mistaking a deliberately omitted older counterpart for corruption.
        if include_events and not runs_truncated and not events_truncated:
            if run_groups.keys() != completion_groups.keys():
                raise AuditLedgerStorageError(
                    "Postgres audit export snapshot has mismatched completion paths"
                )
            replay_run_keys = {key for key in run_groups if key[2] == VERIFICATION_REPLAY_PATH}
            if replay_run_keys != replay_groups.keys():
                raise AuditLedgerStorageError(
                    "Postgres audit export snapshot has incomplete replay provenance"
                )

        for key in run_groups.keys() & completion_groups.keys():
            run = run_groups[key][0]
            completion = completion_groups[key][0]
            if completion.metadata != {"final_decision": run.final_decision.value}:
                raise AuditLedgerStorageError(
                    "Postgres audit export snapshot has mismatched run/completion decisions"
                )

        replay_keys = {
            key
            for key in run_groups.keys() | completion_groups.keys() | replay_groups.keys()
            if key[2] == VERIFICATION_REPLAY_PATH
        }
        for key in replay_keys:
            run_group = run_groups.get(key)
            completion_group = completion_groups.get(key)
            replay_group = replay_groups.get(key)
            if run_group is not None and replay_group is not None:
                _validate_replay_event_contract(replay_group[0], run=run_group[0])
            if completion_group is not None and replay_group is not None:
                if completion_group[0].metadata.get("final_decision") != replay_group[
                    0
                ].metadata.get("replay_final_decision"):
                    raise AuditLedgerStorageError(
                        "Postgres audit export snapshot has mismatched replay provenance"
                    )

    def _select_statement(
        self,
        table: str,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> tuple[str, list[object]]:
        conditions: list[str] = []
        parameters: list[object] = []
        if tenant_id is not None:
            conditions.append("tenant_id = %s")
            parameters.append(tenant_id)
        if trace_id is not None:
            conditions.append("trace_id = %s")
            parameters.append(trace_id)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        parameters.append(limit)
        columns = (
            "id, tenant_id, trace_id, event_id, created_at, payload"
            if table == AUDIT_EVENTS_TABLE
            else "id, tenant_id, trace_id, completion_path, created_at, payload"
        )
        statement = (
            f"SELECT {columns} FROM {table}{where} ORDER BY created_at DESC, id DESC LIMIT %s"
        )
        return statement, parameters

    def _run_from_row(
        self,
        row: Mapping[str, object],
        row_number: int,
    ) -> VerificationRun:
        payload = self._payload_object(row, row_number)
        try:
            run = VerificationRun.model_validate(payload)
        except ValidationError:
            raise AuditLedgerStorageError(
                f"Postgres audit ledger run row {row_number} payload is invalid"
            ) from None
        self._validate_envelope(row, run, row_number)
        return run

    def _loaded_run_from_row(
        self,
        row: Mapping[str, object],
        row_number: int,
    ) -> _LoadedRun:
        run = self._run_from_row(row, row_number)
        completion_path = row.get("completion_path")
        if completion_path is not None and (
            not isinstance(completion_path, str)
            or completion_path not in VERIFICATION_COMPLETION_PATHS
        ):
            raise AuditLedgerStorageError(
                f"Postgres audit ledger run row {row_number} has an invalid completion path"
            )
        if completion_path == VERIFICATION_REPLAY_PATH:
            replay_of = run.input.get("replay_of")
            if not isinstance(replay_of, str) or AUDIT_TRACE_ID_RE.fullmatch(replay_of) is None:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger run row {row_number} has invalid replay provenance"
                )
        return _LoadedRun(run=run, completion_path=completion_path)

    def _completed_run_from_row(
        self,
        row: Mapping[str, object],
        row_number: int,
        *,
        path: str,
    ) -> VerificationRun:
        loaded = self._loaded_run_from_row(row, row_number)
        if loaded.completion_path != path:
            raise AuditLedgerStorageError(
                f"Postgres audit ledger run row {row_number} violates the completion path"
            )
        return loaded.run

    def _event_from_row(
        self,
        row: Mapping[str, object],
        row_number: int,
    ) -> AuditEvent:
        payload = self._payload_object(row, row_number)
        try:
            event = AuditEvent.model_validate(payload)
        except ValidationError:
            raise AuditLedgerStorageError(
                f"Postgres audit ledger event row {row_number} payload is invalid"
            ) from None
        self._validate_envelope(row, event, row_number)
        return event

    def _validate_export_rows(
        self,
        rows: Sequence[Mapping[str, object]],
        *,
        limit: int,
    ) -> None:
        if len(rows) > limit:
            raise AuditLedgerStorageError(
                "Postgres audit ledger export exceeded its requested limit"
            )
        previous_key: tuple[datetime, int] | None = None
        seen_ids: set[int] = set()
        for row_number, row in enumerate(rows, start=1):
            row_id = row.get("id")
            created_at = row.get("created_at")
            if (
                not isinstance(row_id, int)
                or isinstance(row_id, bool)
                or row_id < 1
                or not isinstance(created_at, datetime)
                or created_at.utcoffset() is None
            ):
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger row {row_number} has an invalid ordering envelope"
                )
            if row_id in seen_ids:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger row {row_number} has a duplicate database row ID"
                )
            seen_ids.add(row_id)
            key = created_at, row_id
            if previous_key is not None and key >= previous_key:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger row {row_number} violates export ordering"
                )
            previous_key = key

    def _validate_requested_scope(
        self,
        record: VerificationRun | AuditEvent,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        row_number: int,
    ) -> None:
        if tenant_id is not None and record.tenant_id != tenant_id:
            raise AuditLedgerStorageError(
                f"Postgres audit ledger row {row_number} violates the requested tenant filter"
            )
        if trace_id is not None and record.trace_id != trace_id:
            raise AuditLedgerStorageError(
                f"Postgres audit ledger row {row_number} violates the requested trace filter"
            )

    def _validate_envelope(
        self,
        row: Mapping[str, object],
        record: VerificationRun | AuditEvent,
        row_number: int,
    ) -> None:
        for field_name in ("tenant_id", "trace_id"):
            value = row.get(field_name)
            if not isinstance(value, str) or value != getattr(record, field_name):
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger row {row_number} has a mismatched {field_name} envelope"
                )
        created_at = row.get("created_at")
        if (
            not isinstance(created_at, datetime)
            or created_at.utcoffset() is None
            or record.created_at.utcoffset() is None
            or created_at != record.created_at
        ):
            raise AuditLedgerStorageError(
                f"Postgres audit ledger row {row_number} has a mismatched created_at envelope"
            )
        if isinstance(record, AuditEvent):
            event_id = row.get("event_id")
            if not isinstance(event_id, str) or event_id != record.event_id:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger row {row_number} has a mismatched event_id envelope"
                )

    def _payload_object(
        self,
        row: Mapping[str, object],
        row_number: int,
    ) -> Mapping[str, object]:
        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger row {row_number} payload is not valid JSON"
                ) from exc
        if not isinstance(payload, Mapping):
            raise AuditLedgerStorageError(
                f"Postgres audit ledger row {row_number} payload must be an object"
            )
        return payload


class AuditLedger:
    def __init__(
        self,
        storage_path: Path | None = None,
        *,
        storage: AuditLedgerStorage | None = None,
        export_max_records: int = DEFAULT_EXPORT_MAX_RECORDS,
    ) -> None:
        if storage_path is not None and storage is not None:
            raise AuditLedgerConfigurationError(
                "Configure either storage_path or storage, not both."
            )
        if export_max_records < 1:
            raise AuditLedgerConfigurationError("Audit export max records must be at least 1.")
        self._storage_path = storage_path
        self._storage = storage
        self._export_max_records = export_max_records
        self._runs: list[VerificationRun] = []
        self._events: list[AuditEvent] = []
        self._completed_pairs: dict[tuple[str, str, str], CompletedVerificationRecord] = {}
        self._lock = Lock()
        if self._storage_path is not None:
            self._load_from_storage()

    def append(self, run: VerificationRun) -> None:
        stored_run = _redact_verification_run(run)
        if self._storage is not None:
            self._storage.append_run(_clone_verification_run(stored_run))
            return
        with self._lock:
            self._append_record_locked("verification_run", stored_run)
            self._runs.append(stored_run)

    def append_completed_run(
        self,
        run: VerificationRun,
        *,
        path: str,
    ) -> CompletedVerificationRecord:
        if path not in VERIFICATION_COMPLETION_PATHS:
            raise AuditLedgerError("Verification completion path is not allowlisted.")
        if path == VERIFICATION_REPLAY_PATH:
            raise AuditLedgerError(
                "Replay completions must be persisted with append_replayed_run()."
            )
        event = AuditEvent(
            event_id=f"evt_{uuid4().hex}",
            trace_id=run.trace_id,
            tenant_id=run.tenant_id,
            event_type=VERIFICATION_COMPLETED_EVENT,
            method="POST",
            path=path,
            status_code=200,
            outcome="success",
            metadata={"final_decision": run.final_decision.value},
        )
        return self._append_completion_unit(run=run, event=event)

    def append_replayed_run(
        self,
        run: VerificationRun,
        *,
        source_trace_id: str,
        source_final_decision: FinalDecision,
    ) -> CompletedVerificationRecord:
        decision_changed = source_final_decision != run.final_decision
        completion_event = AuditEvent(
            event_id=f"evt_{uuid4().hex}",
            trace_id=run.trace_id,
            tenant_id=run.tenant_id,
            event_type=VERIFICATION_COMPLETED_EVENT,
            method="POST",
            path=VERIFICATION_REPLAY_PATH,
            status_code=200,
            outcome="success",
            metadata={"final_decision": run.final_decision.value},
        )
        replay_event = AuditEvent(
            event_id=f"evt_{uuid4().hex}",
            trace_id=run.trace_id,
            tenant_id=run.tenant_id,
            event_type=VERIFICATION_REPLAY_EVENT,
            method="POST",
            path=VERIFICATION_REPLAY_PATH,
            status_code=200,
            outcome="success",
            metadata={
                "source_trace_id": source_trace_id,
                "source_final_decision": source_final_decision.value,
                "replay_final_decision": run.final_decision.value,
                "decision_changed": decision_changed,
            },
        )
        return self._append_completion_unit(
            run=run,
            event=completion_event,
            related_events=(replay_event,),
        )

    def _append_completion_unit(
        self,
        *,
        run: VerificationRun,
        event: AuditEvent,
        related_events: Sequence[AuditEvent] = (),
    ) -> CompletedVerificationRecord:
        _validate_completed_pair(
            persisted_run=run,
            persisted_event=event,
            persisted_related_events=related_events,
            expected_run=run,
            expected_event=event,
            expected_related_events=related_events,
        )
        stored_run = _redact_verification_run(run)
        stored_event = _redact_audit_event(event)
        stored_related_events = tuple(
            _redact_audit_event(candidate) for candidate in related_events
        )
        _validate_completed_pair(
            persisted_run=stored_run,
            persisted_event=stored_event,
            persisted_related_events=stored_related_events,
            expected_run=stored_run,
            expected_event=stored_event,
            expected_related_events=stored_related_events,
        )
        if self._storage is not None:
            persisted = self._storage.append_run_with_event(
                run=_clone_verification_run(stored_run),
                event=_clone_audit_event(stored_event),
                related_events=tuple(
                    _clone_audit_event(candidate) for candidate in stored_related_events
                ),
            )
            return _clone_completed_verification_record(persisted)
        with self._lock:
            existing = self._completed_pair_locked(
                expected_run=stored_run,
                expected_event=stored_event,
                expected_related_events=stored_related_events,
            )
            if existing is not None:
                return _clone_completed_verification_record(existing)
            self._append_completion_record_locked(
                stored_run,
                stored_event,
                stored_related_events,
            )
            self._runs.append(stored_run)
            self._events.append(stored_event)
            self._events.extend(stored_related_events)
            completed = CompletedVerificationRecord(
                run=stored_run,
                event=stored_event,
                related_events=stored_related_events,
            )
            self._completed_pairs[_completion_key(stored_run, stored_event.path)] = completed
        return _clone_completed_verification_record(completed)

    def append_event(
        self,
        *,
        trace_id: str,
        tenant_id: str,
        event_type: str,
        method: str,
        path: str,
        status_code: int,
        outcome: str,
        metadata: dict[str, object] | None = None,
    ) -> AuditEvent:
        if event_type in {VERIFICATION_COMPLETED_EVENT, VERIFICATION_REPLAY_EVENT}:
            raise AuditLedgerError(
                "verification_completed and verification_replay must be persisted with "
                "append_completed_run() or append_replayed_run()."
            )
        event = AuditEvent(
            event_id=f"evt_{uuid4().hex}",
            trace_id=trace_id,
            tenant_id=tenant_id,
            event_type=event_type,
            method=method,
            path=path,
            status_code=status_code,
            outcome=outcome,
            metadata=metadata or {},
        )
        stored_event = _redact_audit_event(event)
        if self._storage is not None:
            self._storage.append_event(_clone_audit_event(stored_event))
            return _clone_audit_event(stored_event)
        with self._lock:
            self._append_record_locked("audit_event", stored_event)
            self._events.append(stored_event)
        return _clone_audit_event(stored_event)

    def export(
        self, tenant_id: str | None = None, trace_id: str | None = None
    ) -> list[VerificationRun]:
        if self._storage is not None:
            return [
                _clone_verification_run(run)
                for run in self._storage.load_runs(
                    tenant_id=tenant_id,
                    trace_id=trace_id,
                    limit=self._export_max_records,
                )
            ]
        with self._lock:
            runs = [
                run
                for run in self._runs
                if (tenant_id is None or run.tenant_id == tenant_id)
                and (trace_id is None or run.trace_id == trace_id)
            ]
            return [
                _clone_verification_run(run)
                for run in _apply_export_cap(runs, self._export_max_records)
            ]

    def find_replay_source(
        self,
        *,
        tenant_id: str,
        trace_id: str,
    ) -> VerificationRun | None:
        """Resolve exactly one original run before applying any public export cap."""

        if self._storage is not None:
            candidates = self._storage.load_replay_source_candidates(
                tenant_id=tenant_id,
                trace_id=trace_id,
            )
        else:
            candidates = []
            with self._lock:
                for run in reversed(self._runs):
                    if (
                        run.tenant_id == tenant_id
                        and run.trace_id == trace_id
                        and run.input.get("replay_of") is None
                    ):
                        candidates.append(run)
                        if len(candidates) == 2:
                            break
        if len(candidates) > 1:
            raise ReplaySourceConflictError(
                "Verification replay source has multiple original runs."
            )
        return _clone_verification_run(candidates[0]) if candidates else None

    def export_snapshot(
        self,
        tenant_id: str | None = None,
        trace_id: str | None = None,
        *,
        include_events: bool = True,
    ) -> AuditLedgerSnapshot:
        """Return runs/events from one bounded point-in-time storage view."""

        if self._storage is not None:
            return _clone_audit_ledger_snapshot(
                self._storage.load_snapshot(
                    tenant_id=tenant_id,
                    trace_id=trace_id,
                    limit=self._export_max_records,
                    include_events=include_events,
                )
            )
        with self._lock:
            runs = [
                run
                for run in self._runs
                if (tenant_id is None or run.tenant_id == tenant_id)
                and (trace_id is None or run.trace_id == trace_id)
            ]
            events = (
                [
                    event
                    for event in self._events
                    if (tenant_id is None or event.tenant_id == tenant_id)
                    and (trace_id is None or event.trace_id == trace_id)
                ]
                if include_events
                else []
            )
            return AuditLedgerSnapshot(
                runs=tuple(
                    _clone_verification_run(run)
                    for run in _apply_export_cap(runs, self._export_max_records)
                ),
                events=tuple(
                    _clone_audit_event(event)
                    for event in _apply_export_cap(events, self._export_max_records)
                ),
            )

    def export_events(
        self,
        tenant_id: str | None = None,
        trace_id: str | None = None,
    ) -> list[AuditEvent]:
        if self._storage is not None:
            return [
                _clone_audit_event(event)
                for event in self._storage.load_events(
                    tenant_id=tenant_id,
                    trace_id=trace_id,
                    limit=self._export_max_records,
                )
            ]
        with self._lock:
            events = [
                event
                for event in self._events
                if (tenant_id is None or event.tenant_id == tenant_id)
                and (trace_id is None or event.trace_id == trace_id)
            ]
            return [
                _clone_audit_event(event)
                for event in _apply_export_cap(events, self._export_max_records)
            ]

    def page_events(
        self,
        *,
        tenant_id: str,
        event_type: str,
        trace_id: str | None = None,
        before_created_at: datetime | None = None,
        before_event_id: str | None = None,
        limit: int,
    ) -> list[AuditEvent]:
        """Return an uncapped, storage-filtered keyset page in newest-first order."""

        if limit < 1:
            raise ValueError("Audit event page limit must be positive.")
        if (before_created_at is None) != (before_event_id is None):
            raise ValueError("Audit event page cursor fields must be provided together.")
        if before_created_at is not None and before_created_at.tzinfo is None:
            raise ValueError("Audit event page cursor timestamp must include a timezone.")
        if self._storage is not None:
            return [
                _clone_audit_event(event)
                for event in self._storage.load_event_page(
                    tenant_id=tenant_id,
                    event_type=event_type,
                    trace_id=trace_id,
                    before_created_at=before_created_at,
                    before_event_id=before_event_id,
                    limit=limit,
                )
            ]
        with self._lock:
            events = [
                event
                for event in self._events
                if event.tenant_id == tenant_id
                and event.event_type == event_type
                and (trace_id is None or event.trace_id == trace_id)
            ]
            if any(event.created_at.tzinfo is None for event in events):
                raise AuditLedgerStorageError(
                    "Audit event page contains a timestamp without a timezone."
                )
            events.sort(key=lambda event: (event.created_at, event.event_id), reverse=True)
            if before_created_at is not None and before_event_id is not None:
                cursor_key = before_created_at, before_event_id
                events = [
                    event for event in events if (event.created_at, event.event_id) < cursor_key
                ]
            return [_clone_audit_event(event) for event in events[:limit]]

    def _load_from_storage(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        runs: list[VerificationRun] = []
        events: list[AuditEvent] = []
        legacy_runs: list[VerificationRun] = []
        legacy_completion_events: list[AuditEvent] = []
        completed_pairs: dict[tuple[str, str, str], CompletedVerificationRecord] = {}
        with self._storage_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(record, Mapping):
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} must be a JSON object"
                    )
                record_type = record.get("record_type")
                payload = record.get("payload")
                if not isinstance(payload, Mapping):
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} payload must be an object"
                    )
                if record_type == "verification_run":
                    try:
                        run = VerificationRun.model_validate(payload)
                    except ValidationError:
                        raise AuditLedgerStorageError(
                            f"Audit ledger record {line_number} run payload is invalid"
                        ) from None
                    runs.append(run)
                    legacy_runs.append(run)
                elif record_type == "audit_event":
                    try:
                        event = AuditEvent.model_validate(payload)
                    except ValidationError:
                        raise AuditLedgerStorageError(
                            f"Audit ledger record {line_number} event payload is invalid"
                        ) from None
                    events.append(event)
                    if event.event_type == VERIFICATION_COMPLETED_EVENT:
                        legacy_completion_events.append(event)
                elif record_type == "verification_completion":
                    run_payload = payload.get("run")
                    event_payload = payload.get("event")
                    related_event_payloads = payload.get("related_events", [])
                    if (
                        not isinstance(run_payload, Mapping)
                        or not isinstance(event_payload, Mapping)
                        or not isinstance(related_event_payloads, list)
                        or any(
                            not isinstance(candidate, Mapping)
                            for candidate in related_event_payloads
                        )
                    ):
                        raise AuditLedgerStorageError(
                            f"Audit ledger record {line_number} completion payload is invalid"
                        )
                    try:
                        run = VerificationRun.model_validate(run_payload)
                        event = AuditEvent.model_validate(event_payload)
                        related_events = tuple(
                            AuditEvent.model_validate(candidate)
                            for candidate in related_event_payloads
                        )
                    except ValidationError:
                        raise AuditLedgerStorageError(
                            f"Audit ledger record {line_number} completion payload is invalid"
                        ) from None
                    key = _completion_key(run, event.path)
                    if key in completed_pairs:
                        raise AuditLedgerStorageError(
                            f"Audit ledger record {line_number} duplicates a completion pair"
                        )
                    completed_pairs[key] = CompletedVerificationRecord(
                        run=run,
                        event=event,
                        related_events=related_events,
                    )
                    runs.append(run)
                    events.append(event)
                    events.extend(related_events)
                else:
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} has unsupported record_type"
                    )
        completion_counts: dict[tuple[str, str, str], int] = {}
        event_identities: set[tuple[str, str]] = set()
        for event in events:
            event_identity = event.tenant_id, event.event_id
            if event_identity in event_identities:
                raise AuditLedgerStorageError("Audit ledger contains a duplicate tenant event ID.")
            event_identities.add(event_identity)
            if event.event_type == VERIFICATION_COMPLETED_EVENT:
                key = (event.tenant_id, event.trace_id, event.path)
                completion_counts[key] = completion_counts.get(key, 0) + 1
        if any(count != 1 for count in completion_counts.values()):
            raise AuditLedgerStorageError(
                "Audit ledger contains duplicate verification completion events."
            )
        for event in legacy_completion_events:
            key = (event.tenant_id, event.trace_id, event.path)
            if key in completed_pairs:
                raise AuditLedgerStorageError(
                    "Legacy audit completion duplicates a composite completion pair."
                )
            matching_runs = [
                run
                for run in legacy_runs
                if run.tenant_id == event.tenant_id and run.trace_id == event.trace_id
            ]
            matching_events = [
                candidate
                for candidate in legacy_completion_events
                if candidate.tenant_id == event.tenant_id and candidate.trace_id == event.trace_id
            ]
            if len(matching_runs) != 1 or len(matching_events) != 1:
                raise AuditLedgerStorageError(
                    "Legacy audit completion has no unambiguous verification run pair."
                )
            completed_pairs[key] = CompletedVerificationRecord(
                run=matching_runs[0],
                event=event,
            )
        replay_events_by_key: dict[tuple[str, str, str], list[AuditEvent]] = {}
        for event in events:
            if event.event_type == VERIFICATION_REPLAY_EVENT:
                key = (event.tenant_id, event.trace_id, event.path)
                replay_events_by_key.setdefault(key, []).append(event)
        for key, replay_events in replay_events_by_key.items():
            if len(replay_events) != 1:
                raise AuditLedgerStorageError(
                    "Audit ledger replay event has no unique completion unit."
                )
            if key in completed_pairs:
                continue
            replay_event = replay_events[0]
            _validate_replay_event_contract(replay_event)
            if any(candidate_key[:2] == key[:2] for candidate_key in completed_pairs):
                raise AuditLedgerStorageError(
                    "Legacy audit replay has an ambiguous completion unit."
                )
            source_trace_id = replay_event.metadata["source_trace_id"]
            replay_final_decision = replay_event.metadata["replay_final_decision"]
            matching_runs = [
                run
                for run in legacy_runs
                if run.tenant_id == replay_event.tenant_id
                and run.trace_id == replay_event.trace_id
                and run.input.get("replay_of") == source_trace_id
                and run.final_decision.value == replay_final_decision
            ]
            if len(matching_runs) != 1:
                raise AuditLedgerStorageError(
                    "Legacy audit replay has no unambiguous verification run."
                )
            migrated_event_id = (
                "evt_migrated_completion_"
                + hashlib.sha256(
                    f"{replay_event.tenant_id}\0{replay_event.event_id}".encode("utf-8")
                ).hexdigest()[:24]
            )
            migrated_identity = replay_event.tenant_id, migrated_event_id
            if migrated_identity in event_identities:
                raise AuditLedgerStorageError(
                    "Legacy audit replay completion event ID conflicts with existing history."
                )
            completion_event = AuditEvent(
                event_id=migrated_event_id,
                trace_id=replay_event.trace_id,
                tenant_id=replay_event.tenant_id,
                event_type=VERIFICATION_COMPLETED_EVENT,
                method="POST",
                path=VERIFICATION_REPLAY_PATH,
                status_code=200,
                outcome="success",
                metadata={"final_decision": replay_final_decision},
                created_at=replay_event.created_at,
            )
            event_identities.add(migrated_identity)
            replay_index = events.index(replay_event)
            events.insert(replay_index, completion_event)
            completed_pairs[key] = CompletedVerificationRecord(
                run=matching_runs[0],
                event=completion_event,
            )
        for key, completed in tuple(completed_pairs.items()):
            related_events = tuple(replay_events_by_key.get(key, ()))
            if completed.related_events and completed.related_events != related_events:
                raise AuditLedgerStorageError(
                    "Audit ledger completion has inconsistent related events."
                )
            completed_pairs[key] = _validate_completed_pair(
                persisted_run=completed.run,
                persisted_event=completed.event,
                persisted_related_events=related_events,
                expected_run=completed.run,
                expected_event=completed.event,
                expected_related_events=related_events,
            )
        self._runs = runs
        self._events = events
        self._completed_pairs = completed_pairs

    def _completed_pair_locked(
        self,
        *,
        expected_run: VerificationRun,
        expected_event: AuditEvent,
        expected_related_events: Sequence[AuditEvent] = (),
    ) -> CompletedVerificationRecord | None:
        key = _completion_key(expected_run, expected_event.path)
        existing = self._completed_pairs.get(key)
        if existing is None:
            return None
        return _validate_completed_pair(
            persisted_run=existing.run,
            persisted_event=existing.event,
            persisted_related_events=existing.related_events,
            expected_run=expected_run,
            expected_event=expected_event,
            expected_related_events=expected_related_events,
        )

    def _append_record_locked(
        self,
        record_type: str,
        payload: VerificationRun | AuditEvent,
    ) -> None:
        self._append_records_locked(((record_type, payload),))

    def _append_records_locked(
        self,
        records: tuple[tuple[str, VerificationRun | AuditEvent], ...],
    ) -> None:
        if self._storage_path is None:
            return
        lines = []
        for record_type, payload in records:
            record = {
                "record_type": record_type,
                "payload": payload.model_dump(mode="json"),
            }
            lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            with self._storage_path.open("a", encoding="utf-8") as handle:
                handle.write("".join(lines))
        except OSError as exc:
            raise AuditLedgerStorageError("Audit ledger JSONL append failed.") from exc

    def _append_completion_record_locked(
        self,
        run: VerificationRun,
        event: AuditEvent,
        related_events: Sequence[AuditEvent],
    ) -> None:
        if self._storage_path is None:
            return
        record = {
            "record_type": "verification_completion",
            "payload": {
                "run": run.model_dump(mode="json"),
                "event": event.model_dump(mode="json"),
                "related_events": [
                    candidate.model_dump(mode="json") for candidate in related_events
                ],
            },
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            with self._storage_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError as exc:
            raise AuditLedgerStorageError("Audit ledger JSONL append failed.") from exc


def create_audit_ledger(
    settings: Settings,
    *,
    sql_provider: SqlConnectionProvider | None = None,
) -> AuditLedger:
    backend = settings.audit_ledger_backend.strip().lower()
    environment = normalize_environment(settings.environment)
    export_max_records = int(
        getattr(settings, "audit_export_max_records", DEFAULT_EXPORT_MAX_RECORDS)
    )
    if environment in {"production", "staging"} and backend not in {
        "postgres",
        "postgresql",
    }:
        raise AuditLedgerConfigurationError(
            "Production and staging require the PostgreSQL persistent audit ledger backend."
        )
    if backend == "memory":
        return AuditLedger(export_max_records=export_max_records)
    if backend == "jsonl":
        return AuditLedger(
            storage_path=settings.audit_ledger_path, export_max_records=export_max_records
        )
    if backend in {"postgres", "postgresql"}:
        if sql_provider is None:
            raise AuditLedgerConfigurationError(
                "Postgres audit ledger backend requires an injected SqlConnectionProvider."
            )
        return AuditLedger(
            storage=PostgresAuditLedgerStorage(connection=sql_provider),
            export_max_records=export_max_records,
        )
    raise AuditLedgerConfigurationError(
        f"Unsupported audit ledger backend: {settings.audit_ledger_backend}"
    )


def _apply_export_cap(records: list[_RecordT], limit: int) -> list[_RecordT]:
    if len(records) <= limit:
        return records
    return records[len(records) - limit :]


def _clone_verification_run(run: VerificationRun) -> VerificationRun:
    return run.model_copy(deep=True)


def _clone_audit_event(event: AuditEvent) -> AuditEvent:
    return event.model_copy(deep=True)


def _clone_completed_verification_record(
    record: CompletedVerificationRecord,
) -> CompletedVerificationRecord:
    return CompletedVerificationRecord(
        run=_clone_verification_run(record.run),
        event=_clone_audit_event(record.event),
        related_events=tuple(_clone_audit_event(candidate) for candidate in record.related_events),
    )


def _clone_audit_ledger_snapshot(snapshot: AuditLedgerSnapshot) -> AuditLedgerSnapshot:
    return AuditLedgerSnapshot(
        runs=tuple(_clone_verification_run(run) for run in snapshot.runs),
        events=tuple(_clone_audit_event(event) for event in snapshot.events),
    )


def _validate_completed_pair(
    *,
    persisted_run: VerificationRun,
    persisted_event: AuditEvent,
    persisted_related_events: Sequence[AuditEvent] = (),
    expected_run: VerificationRun,
    expected_event: AuditEvent,
    expected_related_events: Sequence[AuditEvent] = (),
) -> CompletedVerificationRecord:
    if (
        not persisted_run.tenant_id
        or persisted_run.tenant_id != persisted_run.tenant_id.strip()
        or AUDIT_TRACE_ID_RE.fullmatch(persisted_run.trace_id) is None
        or persisted_run.created_at.utcoffset() is None
        or not expected_run.tenant_id
        or expected_run.tenant_id != expected_run.tenant_id.strip()
        or AUDIT_TRACE_ID_RE.fullmatch(expected_run.trace_id) is None
        or expected_run.created_at.utcoffset() is None
    ):
        raise AuditLedgerStorageError(
            "Audit completion verification run has an invalid identity or timestamp."
        )
    persisted_payload = _completion_comparison_payload(persisted_run)
    expected_payload = _completion_comparison_payload(expected_run)
    if persisted_payload != expected_payload:
        raise AuditLedgerStorageError(
            "Audit completion retry conflicts with the persisted verification run."
        )
    _validate_completion_event_contract(persisted_event)
    if (
        persisted_event.tenant_id != expected_run.tenant_id
        or persisted_event.trace_id != expected_run.trace_id
        or persisted_event.path != expected_event.path
        or persisted_event.metadata != expected_event.metadata
        or persisted_event.metadata != {"final_decision": persisted_run.final_decision.value}
    ):
        raise AuditLedgerStorageError("Audit completion event does not match its verification run.")
    if len(persisted_related_events) != len(expected_related_events):
        raise AuditLedgerStorageError(
            "Audit completion related events do not match the persisted unit."
        )
    for persisted_related, expected_related in zip(
        persisted_related_events,
        expected_related_events,
        strict=True,
    ):
        _validate_replay_event_contract(persisted_related, run=persisted_run)
        persisted_related_payload = persisted_related.model_dump(
            mode="json",
            exclude={"event_id", "created_at"},
        )
        expected_related_payload = expected_related.model_dump(
            mode="json",
            exclude={"event_id", "created_at"},
        )
        if persisted_related_payload != expected_related_payload:
            raise AuditLedgerStorageError(
                "Audit completion related event conflicts with the persisted unit."
            )
    if persisted_event.path == VERIFICATION_REPLAY_PATH:
        if len(persisted_related_events) != 1:
            raise AuditLedgerStorageError(
                "Replay completion requires exactly one replay audit event."
            )
    elif persisted_related_events:
        raise AuditLedgerStorageError(
            "Non-replay completion contains an unexpected related audit event."
        )
    return CompletedVerificationRecord(
        run=persisted_run,
        event=persisted_event,
        related_events=tuple(persisted_related_events),
    )


def _completion_comparison_payload(run: VerificationRun) -> dict[str, object]:
    # This compares the typed persisted projection, never raw sensitive input.
    # Root integration with Front B must add a keyed, non-exported pre-redaction
    # request commitment if distinct originals that minimize to the same value
    # must be rejected; an unkeyed raw-input digest is intentionally not stored.
    payload = run.model_dump(mode="json", exclude={"created_at"})
    evidence_rows = payload.get("evidence")
    if isinstance(evidence_rows, list):
        for evidence in evidence_rows:
            if not isinstance(evidence, dict):
                continue
            freshness = evidence.get("freshness")
            if isinstance(freshness, dict):
                freshness.pop("retrieved_at", None)
    return payload


def _completion_key(run: VerificationRun, path: str) -> tuple[str, str, str]:
    return run.tenant_id, run.trace_id, path


def _validate_completion_event_contract(event: AuditEvent) -> None:
    final_decision = event.metadata.get("final_decision")
    if (
        event.event_type != VERIFICATION_COMPLETED_EVENT
        or event.method != "POST"
        or event.path not in VERIFICATION_COMPLETION_PATHS
        or event.status_code != 200
        or event.outcome != "success"
        or not event.tenant_id
        or event.tenant_id != event.tenant_id.strip()
        or AUDIT_TRACE_ID_RE.fullmatch(event.trace_id) is None
        or AUDIT_EVENT_ID_RE.fullmatch(event.event_id) is None
        or event.created_at.utcoffset() is None
        or set(event.metadata) != {"final_decision"}
        or not isinstance(final_decision, str)
    ):
        raise AuditLedgerStorageError(
            "Persisted verification completion event violates its contract."
        )
    try:
        FinalDecision(final_decision)
    except ValueError:
        raise AuditLedgerStorageError(
            "Persisted verification completion event has an invalid final decision."
        ) from None


def _validate_replay_event_contract(
    event: AuditEvent,
    *,
    run: VerificationRun | None = None,
) -> None:
    source_trace_id = event.metadata.get("source_trace_id")
    source_final_decision = event.metadata.get("source_final_decision")
    replay_final_decision = event.metadata.get("replay_final_decision")
    decision_changed = event.metadata.get("decision_changed")
    run_replay_of = run.input.get("replay_of") if run is not None else None
    if (
        event.event_type != VERIFICATION_REPLAY_EVENT
        or event.method != "POST"
        or event.path != VERIFICATION_REPLAY_PATH
        or event.status_code != 200
        or event.outcome != "success"
        or not event.tenant_id
        or event.tenant_id != event.tenant_id.strip()
        or AUDIT_TRACE_ID_RE.fullmatch(event.trace_id) is None
        or AUDIT_EVENT_ID_RE.fullmatch(event.event_id) is None
        or event.created_at.utcoffset() is None
        or set(event.metadata)
        != {
            "source_trace_id",
            "source_final_decision",
            "replay_final_decision",
            "decision_changed",
        }
        or not isinstance(source_trace_id, str)
        or AUDIT_TRACE_ID_RE.fullmatch(source_trace_id) is None
        or not isinstance(source_final_decision, str)
        or not isinstance(replay_final_decision, str)
        or not isinstance(decision_changed, bool)
        or (
            run is not None
            and (
                event.tenant_id != run.tenant_id
                or event.trace_id != run.trace_id
                or replay_final_decision != run.final_decision.value
                or run_replay_of != source_trace_id
            )
        )
    ):
        raise AuditLedgerStorageError("Persisted verification replay event violates its contract.")
    try:
        source_decision = FinalDecision(source_final_decision)
        replay_decision = FinalDecision(replay_final_decision)
    except ValueError:
        raise AuditLedgerStorageError(
            "Persisted verification replay event has an invalid final decision."
        ) from None
    if decision_changed != (source_decision != replay_decision):
        raise AuditLedgerStorageError(
            "Persisted verification replay event has an inconsistent decision change."
        )


def _dump_payload(record: VerificationRun | AuditEvent) -> str:
    return json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _redact_verification_run(run: VerificationRun) -> VerificationRun:
    redacted_input = _redact_value(run.input)
    if not isinstance(redacted_input, dict):
        raise AuditLedgerStorageError("Audit run input redaction produced an invalid object.")
    replay_of = run.input.get("replay_of")
    if isinstance(replay_of, str) and AUDIT_TRACE_ID_RE.fullmatch(replay_of) is not None:
        # replay_of is a validated relational identity, not free-form content.
        redacted_input["replay_of"] = replay_of
    redacted = run.model_copy(
        update={
            "input": redacted_input,
            "claims": [
                claim.model_copy(
                    update={
                        "text": _redact_text(claim.text),
                        "canonical_form": _redact_text(claim.canonical_form),
                        "metadata": _redact_value(claim.metadata),
                    }
                )
                for claim in run.claims
            ],
            "evidence": [
                evidence.model_copy(
                    update={
                        "source_ref": _redact_text(evidence.source_ref),
                        "content": _redact_text(evidence.content),
                        "structured_content": _redact_value(evidence.structured_content),
                    }
                )
                for evidence in run.evidence
            ],
            "verdicts": [
                verdict.model_copy(
                    update={
                        "reason": _redact_text(verdict.reason),
                        "validator_trace": _redact_value(verdict.validator_trace),
                    }
                )
                for verdict in run.verdicts
            ],
            "final_text": _redact_text(run.final_text),
        },
        deep=True,
    )
    # Pydantic applies ``update`` values after its deepcopy. Clone the completed
    # projection once more so unmodified nested child fields cannot alias ingress.
    return _clone_verification_run(redacted)


def _redact_audit_event(event: AuditEvent) -> AuditEvent:
    redacted_metadata = _redact_value(event.metadata)
    if not isinstance(redacted_metadata, dict):
        raise AuditLedgerStorageError("Audit event metadata redaction produced an invalid object.")
    source_trace_id = event.metadata.get("source_trace_id")
    if (
        event.event_type == VERIFICATION_REPLAY_EVENT
        and isinstance(source_trace_id, str)
        and AUDIT_TRACE_ID_RE.fullmatch(source_trace_id) is not None
    ):
        # Replay provenance must retain its validated structural source identity.
        redacted_metadata["source_trace_id"] = source_trace_id
    redacted = event.model_copy(update={"metadata": redacted_metadata}, deep=True)
    return _clone_audit_event(redacted)


def _redact_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive_key(str(key)) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(value: str) -> str:
    lowered = value.lower()
    if any(keyword in lowered for keyword in SENSITIVE_KEYWORDS):
        return REDACTED
    redacted = value
    for pattern in SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)
