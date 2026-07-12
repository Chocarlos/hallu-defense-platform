from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from pydantic import ValidationError

from hallu_defense.services.audit import (
    VERIFICATION_COMPLETED_EVENT,
    VERIFICATION_COMPLETION_PATHS,
)
from hallu_defense.domain.models import (
    AuditEvent,
    FinalDecision,
    VerificationRunListRequest,
    VerificationRunSummary,
)

_CURSOR_VERSION = 1
_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_EVENT_ID_RE = re.compile(r"^evt_[A-Za-z0-9_-]+$")
_TRACE_ID_RE = re.compile(r"^tr_[A-Za-z0-9_-]{8,80}$")


class VerificationHistoryError(RuntimeError):
    """Base error for the durable verification history view."""


class VerificationHistoryCursorError(VerificationHistoryError):
    """Raised when a client-provided pagination cursor is malformed."""


class VerificationHistoryIntegrityError(VerificationHistoryError):
    """Raised when a persisted completion event violates its safe contract."""


class AuditEventReader(Protocol):
    def page_events(
        self,
        *,
        tenant_id: str,
        event_type: str,
        trace_id: str | None = None,
        before_created_at: datetime | None = None,
        before_event_id: str | None = None,
        limit: int,
    ) -> list[AuditEvent]: ...


@dataclass(frozen=True)
class _HistoryRow:
    event_id: str
    summary: VerificationRunSummary

    @property
    def sort_key(self) -> tuple[datetime, str]:
        return self.summary.created_at, self.event_id


def list_verification_history(
    reader: AuditEventReader,
    *,
    tenant_id: str,
    request: VerificationRunListRequest,
) -> tuple[list[VerificationRunSummary], str | None]:
    """Return a newest-first page derived only from durable completion events."""

    cursor_key = _decode_cursor(request.cursor) if request.cursor is not None else None
    events = reader.page_events(
        tenant_id=tenant_id,
        event_type=VERIFICATION_COMPLETED_EVENT,
        trace_id=request.trace_id,
        before_created_at=cursor_key[0] if cursor_key is not None else None,
        before_event_id=cursor_key[1] if cursor_key is not None else None,
        limit=request.limit + 1,
    )
    rows = [
        _event_to_row(
            event,
            tenant_id=tenant_id,
            trace_id=request.trace_id,
        )
        for event in events
    ]
    page_rows = rows[: request.limit]
    next_cursor = None
    if len(events) > request.limit and page_rows:
        next_cursor = _encode_cursor(page_rows[-1])
    return [row.summary for row in page_rows], next_cursor


def _event_to_row(
    event: AuditEvent,
    *,
    tenant_id: str,
    trace_id: str | None,
) -> _HistoryRow:
    if event.tenant_id != tenant_id:
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event violates the requested tenant."
        )
    if trace_id is not None and event.trace_id != trace_id:
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event violates the requested trace."
        )
    if (
        event.event_type != VERIFICATION_COMPLETED_EVENT
        or event.method != "POST"
        or event.path not in VERIFICATION_COMPLETION_PATHS
        or event.status_code != 200
        or event.outcome != "success"
        or not _TRACE_ID_RE.fullmatch(event.trace_id)
        or not _EVENT_ID_RE.fullmatch(event.event_id)
        or event.created_at.utcoffset() is None
    ):
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event is invalid."
        )
    final_decision = event.metadata.get("final_decision")
    if not isinstance(final_decision, str):
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event is missing final_decision."
        )
    try:
        decision = FinalDecision(final_decision)
    except ValueError:
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event has an invalid final_decision."
        ) from None
    if set(event.metadata) != {"final_decision"}:
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event is invalid."
        )
    try:
        summary = VerificationRunSummary(
            trace_id=event.trace_id,
            final_decision=decision,
            created_at=event.created_at,
        )
    except ValidationError:
        raise VerificationHistoryIntegrityError(
            "Persisted verification completion event is invalid."
        ) from None
    return _HistoryRow(event_id=event.event_id, summary=summary)


def _encode_cursor(row: _HistoryRow) -> str:
    payload = json.dumps(
        {
            "created_at": row.summary.created_at.isoformat(),
            "event_id": row.event_id,
            "version": _CURSOR_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    if not _CURSOR_RE.fullmatch(cursor):
        raise VerificationHistoryCursorError("Verification history cursor is invalid.")
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerificationHistoryCursorError("Verification history cursor is invalid.") from exc
    if not isinstance(payload, dict) or set(payload) != {"created_at", "event_id", "version"}:
        raise VerificationHistoryCursorError("Verification history cursor is invalid.")
    if payload["version"] != _CURSOR_VERSION or not isinstance(payload["event_id"], str):
        raise VerificationHistoryCursorError("Verification history cursor is invalid.")
    event_id = payload["event_id"]
    if not _EVENT_ID_RE.fullmatch(event_id) or not isinstance(payload["created_at"], str):
        raise VerificationHistoryCursorError("Verification history cursor is invalid.")
    try:
        created_at = datetime.fromisoformat(payload["created_at"])
    except ValueError as exc:
        raise VerificationHistoryCursorError("Verification history cursor is invalid.") from exc
    if created_at.tzinfo is None:
        raise VerificationHistoryCursorError("Verification history cursor is invalid.")
    return created_at, event_id
