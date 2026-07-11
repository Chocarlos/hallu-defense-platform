from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Protocol, TypeVar
from uuid import uuid4

from pydantic import ValidationError

from hallu_defense.config import Settings, normalize_environment
from hallu_defense.domain.models import AuditEvent, VerificationRun
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
    re.compile(
        r"(?i)([?&](?:sig|signature|token|access_token|x-amz-signature)=)[^&#\s]+"
    ),
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
VERIFICATION_COMPLETED_EVENT = "verification_completed"
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


class AuditLedgerStorage(Protocol):
    """Persistence seam for the audit ledger.

    Implementations receive verification runs and audit events that have already
    been redacted by :class:`AuditLedger`; they must never re-derive or log the
    original payloads. ``load_*`` returns at most ``limit`` of the most recent
    records for the requested tenant/trace filter, in chronological order.
    """

    def append_run(self, run: VerificationRun) -> None:
        ...

    def append_event(self, event: AuditEvent) -> None:
        ...

    def append_run_with_event(
        self,
        *,
        run: VerificationRun,
        event: AuditEvent,
    ) -> None:
        ...

    def load_runs(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[VerificationRun]:
        ...

    def load_events(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[AuditEvent]:
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
    ) -> None:
        with self._connection.transaction() as transaction:
            self._insert_run(transaction, run)
            self._insert_event(transaction, event)

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
        statement, parameters = self._select_statement(
            AUDIT_RUNS_TABLE, tenant_id=tenant_id, trace_id=trace_id, limit=limit
        )
        rows = self._connection.fetch_all(statement, parameters)
        runs: list[VerificationRun] = []
        for row_number, row in enumerate(rows, start=1):
            payload = self._payload_object(row, row_number)
            try:
                run = VerificationRun.model_validate(payload)
            except ValidationError as exc:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger run row {row_number} payload is invalid"
                ) from exc
            self._validate_envelope(row, run, row_number)
            runs.append(run)
        runs.reverse()
        return runs

    def load_events(
        self,
        *,
        tenant_id: str | None,
        trace_id: str | None,
        limit: int,
    ) -> list[AuditEvent]:
        statement, parameters = self._select_statement(
            AUDIT_EVENTS_TABLE, tenant_id=tenant_id, trace_id=trace_id, limit=limit
        )
        rows = self._connection.fetch_all(statement, parameters)
        events: list[AuditEvent] = []
        for row_number, row in enumerate(rows, start=1):
            payload = self._payload_object(row, row_number)
            try:
                event = AuditEvent.model_validate(payload)
            except ValidationError as exc:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} payload is invalid"
                ) from exc
            self._validate_envelope(row, event, row_number)
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
            "SELECT tenant_id, trace_id, event_id, created_at, payload "
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
        for row_number, row in enumerate(rows, start=1):
            payload = self._payload_object(row, row_number)
            try:
                event = AuditEvent.model_validate(payload)
            except ValidationError as exc:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} payload is invalid"
                ) from exc
            self._validate_envelope(row, event, row_number)
            if (
                event.tenant_id != tenant_id
                or event.event_type != event_type
                or (trace_id is not None and event.trace_id != trace_id)
            ):
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} violates page filters"
                )
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
            if previous_key is not None and event_key > previous_key:
                raise AuditLedgerStorageError(
                    f"Postgres audit ledger event row {row_number} violates page ordering"
                )
            previous_key = event_key
            events.append(event)
        return events

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
            "tenant_id, trace_id, event_id, created_at, payload"
            if table == AUDIT_EVENTS_TABLE
            else "tenant_id, trace_id, created_at, payload"
        )
        statement = (
            f"SELECT {columns} FROM {table}{where} "
            "ORDER BY created_at DESC, id DESC LIMIT %s"
        )
        return statement, parameters

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
        self._storage_path = storage_path
        self._storage = storage
        self._export_max_records = export_max_records
        self._runs: list[VerificationRun] = []
        self._events: list[AuditEvent] = []
        self._lock = Lock()
        if self._storage_path is not None:
            self._load_from_storage()

    def append(self, run: VerificationRun) -> None:
        stored_run = _redact_verification_run(run)
        if self._storage is not None:
            self._storage.append_run(stored_run)
            return
        with self._lock:
            self._append_record_locked("verification_run", stored_run)
            self._runs.append(stored_run)

    def append_completed_run(
        self,
        run: VerificationRun,
        *,
        path: str,
    ) -> AuditEvent:
        if path not in VERIFICATION_COMPLETION_PATHS:
            raise AuditLedgerError("Verification completion path is not allowlisted.")
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
        stored_run = _redact_verification_run(run)
        stored_event = _redact_audit_event(event)
        if self._storage is not None:
            self._storage.append_run_with_event(
                run=stored_run,
                event=stored_event,
            )
            return stored_event
        with self._lock:
            self._append_records_locked(
                (
                    ("verification_run", stored_run),
                    ("audit_event", stored_event),
                )
            )
            self._runs.append(stored_run)
            self._events.append(stored_event)
        return stored_event

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
            self._storage.append_event(stored_event)
            return stored_event
        with self._lock:
            self._append_record_locked("audit_event", stored_event)
            self._events.append(stored_event)
        return stored_event

    def export(self, tenant_id: str | None = None, trace_id: str | None = None) -> list[VerificationRun]:
        if self._storage is not None:
            return self._storage.load_runs(
                tenant_id=tenant_id,
                trace_id=trace_id,
                limit=self._export_max_records,
            )
        with self._lock:
            runs = list(self._runs)
        if tenant_id is not None:
            runs = [run for run in runs if run.tenant_id == tenant_id]
        if trace_id is not None:
            runs = [run for run in runs if run.trace_id == trace_id]
        return _apply_export_cap(runs, self._export_max_records)

    def export_events(
        self,
        tenant_id: str | None = None,
        trace_id: str | None = None,
    ) -> list[AuditEvent]:
        if self._storage is not None:
            return self._storage.load_events(
                tenant_id=tenant_id,
                trace_id=trace_id,
                limit=self._export_max_records,
            )
        with self._lock:
            events = list(self._events)
        if tenant_id is not None:
            events = [event for event in events if event.tenant_id == tenant_id]
        if trace_id is not None:
            events = [event for event in events if event.trace_id == trace_id]
        return _apply_export_cap(events, self._export_max_records)

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
            return self._storage.load_event_page(
                tenant_id=tenant_id,
                event_type=event_type,
                trace_id=trace_id,
                before_created_at=before_created_at,
                before_event_id=before_event_id,
                limit=limit,
            )
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
                event
                for event in events
                if (event.created_at, event.event_id) < cursor_key
            ]
        return events[:limit]

    def _load_from_storage(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        runs: list[VerificationRun] = []
        events: list[AuditEvent] = []
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
                    runs.append(VerificationRun.model_validate(payload))
                elif record_type == "audit_event":
                    events.append(AuditEvent.model_validate(payload))
                else:
                    raise AuditLedgerStorageError(
                        f"Audit ledger record {line_number} has unsupported record_type"
                    )
        self._runs = runs
        self._events = events

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
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for record_type, payload in records:
            record = {
                "record_type": record_type,
                "payload": payload.model_dump(mode="json"),
            }
            lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write("".join(lines))


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
        return AuditLedger(storage_path=settings.audit_ledger_path,
                           export_max_records=export_max_records)
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


def _dump_payload(record: VerificationRun | AuditEvent) -> str:
    return json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _redact_verification_run(run: VerificationRun) -> VerificationRun:
    return run.model_copy(
        update={
            "input": _redact_value(run.input),
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


def _redact_audit_event(event: AuditEvent) -> AuditEvent:
    return event.model_copy(update={"metadata": _redact_value(event.metadata)}, deep=True)


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
