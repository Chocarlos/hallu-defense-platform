from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4

from pydantic import ValidationError

from hallu_defense.config import Settings, normalize_environment
from hallu_defense.domain.models import (
    ApprovalDecision,
    ApprovalDecisionRequest,
    ApprovalExecutionGrant,
    ApprovalListRequest,
    ApprovalRecord,
    ApprovalStatus,
    ToolCallEnvelope,
)
from hallu_defense.services.postgres import SqlConnectionProvider
from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
)

SENSITIVE_KEY_RE = re.compile(r"(api[_-]?key|secret|token|password)", re.I)
REDACTED = "[REDACTED]"
TOOL_CALL_COMMITMENT_DOMAIN = b"hallu-defense:approval-tool-call:v1\x00"
TOOL_CALL_COMMITMENT_STORAGE_KEY = "_hallu_tool_call_commitment_v1"
TOOL_CALL_COMMITMENT_RE = re.compile(r"^(?:hmac-)?sha256:[0-9a-f]{64}$")
MIN_COMMITMENT_KEY_BYTES = 32


class ApprovalError(Exception):
    """Base error for approval queue operations."""


class ApprovalNotFoundError(ApprovalError):
    """Raised when an approval is missing or belongs to another tenant."""


class ApprovalAlreadyDecidedError(ApprovalError):
    """Raised when a caller tries to decide an approval more than once."""


class ApprovalDecisionIdentityError(ApprovalError):
    """Raised when an approval decision has no authenticated reviewer identity."""


class ApprovalQueueConfigurationError(ApprovalError):
    """Raised when approval queue configuration is unsafe or unsupported."""


class ApprovalQueueStorageError(ApprovalError):
    """Raised when approval queue storage cannot be read safely."""


class ApprovalExecutionGrantError(ApprovalError):
    """Raised when an approval execution grant is missing, invalid, or unusable."""


class ApprovalExecutionGrantConsumedError(ApprovalExecutionGrantError):
    """Raised when an approval execution grant is reused."""


class ApprovalExecutionGrantExpiredError(ApprovalExecutionGrantError):
    """Raised when an approval execution grant is expired."""


@dataclass(frozen=True)
class ApprovalDecisionResult:
    approval: ApprovalRecord
    execution_grant: ApprovalExecutionGrant | None = None


@dataclass(frozen=True)
class ApprovalExecutionGrantState:
    approval_id: str
    tenant_id: str
    tool_call_fingerprint: str
    token_hash: str
    expires_at: datetime
    consumed_at: datetime | None = None


def _set_record_tool_call_commitment(
    record: ApprovalRecord,
    commitment: object,
) -> None:
    if commitment is None:
        record._tool_call_commitment = None
        return
    if not isinstance(commitment, str) or TOOL_CALL_COMMITMENT_RE.fullmatch(commitment) is None:
        raise ApprovalQueueStorageError("Approval record tool-call commitment is invalid.")
    record._tool_call_commitment = commitment


def _record_tool_call_commitment(
    record: ApprovalRecord,
    *,
    required: bool,
) -> str | None:
    commitment = record._tool_call_commitment
    if commitment is None:
        if required:
            raise ApprovalQueueStorageError(
                "Approval record is missing its original tool-call commitment."
            )
        return None
    if TOOL_CALL_COMMITMENT_RE.fullmatch(commitment) is None:
        raise ApprovalQueueStorageError("Approval record tool-call commitment is invalid.")
    return commitment


# --- PostgreSQL backend -------------------------------------------------------
#
# The decide-once and consume-once guards below are the security core of the
# durable backend: each is a single UPDATE ... RETURNING statement whose WHERE
# clause is the invariant. The database, not the process, enforces "at most one"
# so concurrent API workers cannot double-decide an approval or double-spend an
# execution grant. Never replace these with a read-then-write that drops the
# guard.
_INSERT_RECORD_SQL = (
    "INSERT INTO approval_records "
    "(approval_id, tenant_id, trace_id, status, payload, created_at) "
    "VALUES (%s, %s, %s, %s, %s::jsonb, %s)"
)
_LIST_RECORDS_SQL = (
    "SELECT payload FROM approval_records WHERE tenant_id=%s ORDER BY created_at ASC"
)
_GET_RECORD_SQL = "SELECT payload FROM approval_records WHERE approval_id=%s AND tenant_id=%s"
_DECIDE_ONCE_SQL = (
    "UPDATE approval_records SET status=%s, decided_at=%s, payload=%s::jsonb "
    "WHERE approval_id=%s AND tenant_id=%s AND status='pending' RETURNING approval_id"
)
_INSERT_GRANT_SQL = (
    "INSERT INTO approval_execution_grants "
    "(token_hash, approval_id, tenant_id, tool_call_fingerprint, expires_at, consumed_at, "
    "created_at) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s)"
)
_CONSUME_GRANT_ONCE_SQL = (
    "UPDATE approval_execution_grants SET consumed_at=now() "
    "WHERE token_hash=%s AND approval_id=%s AND tenant_id=%s "
    "AND tool_call_fingerprint=%s "
    "AND consumed_at IS NULL AND expires_at > now() RETURNING approval_id"
)
_SELECT_GRANT_SQL = (
    "SELECT consumed_at, expires_at FROM approval_execution_grants "
    "WHERE token_hash=%s AND approval_id=%s AND tenant_id=%s "
    "AND tool_call_fingerprint=%s"
)


class ApprovalQueueStorage(Protocol):
    """Durable persistence seam for :class:`ApprovalQueue`.

    Implementations own persistence plus the two atomic guards; the queue keeps
    every policy/redaction/commitment decision. ``decide_with_grant_once`` and
    ``consume_grant_once`` MUST be atomic single-use operations.
    """

    def insert_record(self, record: ApprovalRecord) -> None: ...

    def list_records(self, tenant_id: str) -> list[ApprovalRecord]: ...

    def get_record(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None: ...

    def decide_with_grant_once(
        self,
        *,
        decided: ApprovalRecord,
        grant_state: ApprovalExecutionGrantState | None,
    ) -> None:
        """Atomically persist the guarded decision and its optional grant."""
        ...

    def consume_grant_once(
        self,
        *,
        tenant_id: str,
        approval_id: str,
        token_hash: str,
        tool_call_fingerprint: str,
        now: datetime,
    ) -> str:
        """Consume the matching grant once; raise the specific error otherwise."""
        ...


class PostgresApprovalQueueStorage:
    """Atomic PostgreSQL storage backend for the approval queue.

    The redacted ``ApprovalRecord`` snapshot is the source of truth, stored as
    ``jsonb`` via ``model_dump(mode="json")`` exactly like the JSONL backend, so
    secrets are never written raw. Decision plus optional execution grant share
    one provider transaction; ``UPDATE ... RETURNING`` and the consume guard
    enforce single-use under concurrency.
    """

    def __init__(
        self,
        *,
        connection: SqlConnectionProvider,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def insert_record(self, record: ApprovalRecord) -> None:
        self._connection.execute(
            _INSERT_RECORD_SQL,
            (
                record.approval_id,
                record.tenant_id,
                record.trace_id,
                record.status.value,
                self._payload(record),
                record.created_at,
            ),
        )

    def list_records(self, tenant_id: str) -> list[ApprovalRecord]:
        rows = self._connection.fetch_all(_LIST_RECORDS_SQL, (tenant_id,))
        return [self._record_from_row(row, index) for index, row in enumerate(rows, start=1)]

    def get_record(self, tenant_id: str, approval_id: str) -> ApprovalRecord | None:
        rows = self._connection.fetch_all(_GET_RECORD_SQL, (approval_id, tenant_id))
        if not rows:
            return None
        return self._record_from_row(rows[0], 1)

    def decide_with_grant_once(
        self,
        *,
        decided: ApprovalRecord,
        grant_state: ApprovalExecutionGrantState | None,
    ) -> None:
        with self._connection.transaction() as transaction:
            rows = transaction.execute_returning(
                _DECIDE_ONCE_SQL,
                (
                    decided.status.value,
                    decided.decided_at,
                    self._payload(decided),
                    decided.approval_id,
                    decided.tenant_id,
                ),
            )
            if not rows:
                raise ApprovalAlreadyDecidedError("Approval has already been decided.")
            if grant_state is not None:
                transaction.execute(
                    _INSERT_GRANT_SQL,
                    (
                        grant_state.token_hash,
                        grant_state.approval_id,
                        grant_state.tenant_id,
                        grant_state.tool_call_fingerprint,
                        grant_state.expires_at,
                        grant_state.consumed_at,
                        self._now(),
                    ),
                )

    def consume_grant_once(
        self,
        *,
        tenant_id: str,
        approval_id: str,
        token_hash: str,
        tool_call_fingerprint: str,
        now: datetime,
    ) -> str:
        rows = self._connection.execute_returning(
            _CONSUME_GRANT_ONCE_SQL,
            (token_hash, approval_id, tenant_id, tool_call_fingerprint),
        )
        if rows:
            returned_approval_id = rows[0].get("approval_id")
            if returned_approval_id != approval_id:
                raise ApprovalQueueStorageError(
                    "Approval execution grant consume returned an inconsistent approval_id."
                )
            return approval_id
        # 0 rows: the atomic guard rejected the grant. Disambiguate against the
        # JSONL taxonomy without ever un-guarding the write above.
        grant_rows = self._connection.fetch_all(
            _SELECT_GRANT_SQL,
            (token_hash, approval_id, tenant_id, tool_call_fingerprint),
        )
        if not grant_rows:
            raise ApprovalExecutionGrantError("Approval execution grant is invalid.")
        grant = grant_rows[0]
        if self._coerce_optional_datetime(grant.get("consumed_at")) is not None:
            raise ApprovalExecutionGrantConsumedError(
                "Approval execution grant has already been consumed."
            )
        expires_at = self._coerce_optional_datetime(grant.get("expires_at"))
        if expires_at is not None and expires_at <= now:
            raise ApprovalExecutionGrantExpiredError("Approval execution grant has expired.")
        raise ApprovalExecutionGrantError("Approval execution grant does not match this tool call.")

    def _payload(self, record: ApprovalRecord) -> str:
        payload = record.model_dump(mode="json")
        commitment = _record_tool_call_commitment(record, required=False)
        if commitment is not None:
            payload[TOOL_CALL_COMMITMENT_STORAGE_KEY] = commitment
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _record_from_row(self, row: Mapping[str, object], row_number: int) -> ApprovalRecord:
        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ApprovalQueueStorageError(
                    f"Postgres approval record {row_number} payload is not valid JSON"
                ) from exc
        if not isinstance(payload, Mapping):
            raise ApprovalQueueStorageError(
                f"Postgres approval record {row_number} payload must be an object"
            )
        stored_payload = dict(payload)
        commitment = stored_payload.pop(TOOL_CALL_COMMITMENT_STORAGE_KEY, None)
        try:
            record = ApprovalRecord.model_validate(stored_payload)
        except ValidationError as exc:
            raise ApprovalQueueStorageError(
                f"Postgres approval record {row_number} payload is invalid"
            ) from exc
        _set_record_tool_call_commitment(record, commitment)
        return record

    def _coerce_optional_datetime(self, value: object) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        raise ApprovalQueueStorageError("Approval execution grant timestamp is invalid.")

    def _now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)


class ApprovalQueue:
    def __init__(
        self,
        storage_path: Path | None = None,
        *,
        storage: ApprovalQueueStorage | None = None,
        execution_grant_ttl_seconds: int = 900,
        commitment_key: bytes | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if storage_path is not None and storage is not None:
            raise ApprovalQueueConfigurationError(
                "Configure either storage_path or storage, not both."
            )
        self._storage_path = storage_path
        self._storage = storage
        self._execution_grant_ttl = timedelta(seconds=execution_grant_ttl_seconds)
        if commitment_key is not None and (
            not isinstance(commitment_key, bytes) or len(commitment_key) < MIN_COMMITMENT_KEY_BYTES
        ):
            raise ApprovalQueueConfigurationError(
                "Approval tool-call commitment key must contain at least 32 bytes."
            )
        self._commitment_key = commitment_key
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._records: dict[str, ApprovalRecord] = {}
        self._grants: dict[str, ApprovalExecutionGrantState] = {}
        if self._storage_path is not None:
            self._load_from_storage()

    def request_approval(
        self,
        *,
        tenant_id: str,
        trace_id: str,
        tool_call: ToolCallEnvelope,
        reason: str,
        requested_by: str = "system",
    ) -> ApprovalRecord:
        commitment = self._tool_call_commitment(tool_call)
        record = ApprovalRecord(
            approval_id=f"apr_{uuid4().hex}",
            tenant_id=tenant_id,
            trace_id=trace_id,
            tool_call=self._sanitize_tool_call(tool_call),
            status=ApprovalStatus.PENDING,
            risk_level=tool_call.risk_level,
            reason=reason,
            requested_by=requested_by,
        )
        _set_record_tool_call_commitment(record, commitment)
        if self._storage is not None:
            self._storage.insert_record(record)
            return record
        with self._lock:
            self._append_record_locked(record)
            self._records[record.approval_id] = record
        return record

    def list_for_tenant(self, tenant_id: str, request: ApprovalListRequest) -> list[ApprovalRecord]:
        if self._storage is not None:
            records = self._storage.list_records(tenant_id)
        else:
            with self._lock:
                records = list(self._records.values())
        filtered = [
            record
            for record in records
            if record.tenant_id == tenant_id
            and (request.status is None or record.status == request.status)
            and (request.trace_id is None or record.trace_id == request.trace_id)
        ]
        return sorted(filtered, key=lambda record: record.created_at)

    def decide(self, tenant_id: str, request: ApprovalDecisionRequest) -> ApprovalRecord:
        return self.decide_with_grant(tenant_id, request).approval

    def decide_with_grant(
        self,
        tenant_id: str,
        request: ApprovalDecisionRequest,
    ) -> ApprovalDecisionResult:
        if self._storage is not None:
            return self._decide_with_grant_via_storage(tenant_id, request)
        with self._lock:
            record = self._records.get(request.approval_id)
            if record is None or record.tenant_id != tenant_id:
                raise ApprovalNotFoundError("Approval was not found for this tenant.")
            if record.status != ApprovalStatus.PENDING:
                raise ApprovalAlreadyDecidedError("Approval has already been decided.")
            if not request.decided_by:
                raise ApprovalDecisionIdentityError("Approval decision requires reviewer identity.")

            status = (
                ApprovalStatus.APPROVED
                if request.decision == ApprovalDecision.APPROVE
                else ApprovalStatus.REJECTED
            )
            decided = record.model_copy(
                update={
                    "status": status,
                    "decided_by": request.decided_by,
                    "decision_reason": request.reason,
                    "decided_at": self._now(),
                }
            )
            execution_grant: ApprovalExecutionGrant | None = None
            grant_state: ApprovalExecutionGrantState | None = None
            if status == ApprovalStatus.APPROVED:
                grant_state, execution_grant = self._create_execution_grant(record)
                self._append_grant_state_locked(grant_state)
            self._append_record_locked(decided)
            if grant_state is not None:
                self._grants[request.approval_id] = grant_state
            self._records[request.approval_id] = decided
            return ApprovalDecisionResult(approval=decided, execution_grant=execution_grant)

    def consume_execution_grant(
        self,
        tenant_id: str,
        tool_call: ToolCallEnvelope,
    ) -> ApprovalRecord:
        if not tool_call.approval_id or not tool_call.approval_execution_token:
            raise ApprovalExecutionGrantError("Approval execution grant is required.")
        if self._storage is not None:
            return self._consume_execution_grant_via_storage(tenant_id, tool_call)
        with self._lock:
            record = self._records.get(tool_call.approval_id)
            if record is None or record.tenant_id != tenant_id:
                raise ApprovalNotFoundError("Approval was not found for this tenant.")
            if record.status != ApprovalStatus.APPROVED:
                raise ApprovalExecutionGrantError("Approval has not been approved.")

            grant_state = self._grants.get(tool_call.approval_id)
            if grant_state is None or grant_state.tenant_id != tenant_id:
                raise ApprovalExecutionGrantError("Approval execution grant was not found.")
            if grant_state.consumed_at is not None:
                raise ApprovalExecutionGrantConsumedError(
                    "Approval execution grant has already been consumed."
                )
            if grant_state.expires_at <= self._now():
                raise ApprovalExecutionGrantExpiredError("Approval execution grant has expired.")
            if not hmac.compare_digest(
                grant_state.token_hash,
                self._hash_execution_token(tool_call.approval_execution_token),
            ):
                raise ApprovalExecutionGrantError("Approval execution grant is invalid.")
            if not hmac.compare_digest(
                grant_state.tool_call_fingerprint,
                self._tool_call_commitment(tool_call),
            ):
                raise ApprovalExecutionGrantError(
                    "Approval execution grant does not match this tool call."
                )

            consumed_state = replace(grant_state, consumed_at=self._now())
            self._append_grant_state_locked(consumed_state)
            self._grants[tool_call.approval_id] = consumed_state
            return record

    def _decide_with_grant_via_storage(
        self,
        tenant_id: str,
        request: ApprovalDecisionRequest,
    ) -> ApprovalDecisionResult:
        assert self._storage is not None
        record = self._storage.get_record(tenant_id, request.approval_id)
        if record is None or record.tenant_id != tenant_id:
            raise ApprovalNotFoundError("Approval was not found for this tenant.")
        if record.status != ApprovalStatus.PENDING:
            raise ApprovalAlreadyDecidedError("Approval has already been decided.")
        if not request.decided_by:
            raise ApprovalDecisionIdentityError("Approval decision requires reviewer identity.")

        status = (
            ApprovalStatus.APPROVED
            if request.decision == ApprovalDecision.APPROVE
            else ApprovalStatus.REJECTED
        )
        decided = self._sanitize_record(
            record.model_copy(
                update={
                    "status": status,
                    "decided_by": request.decided_by,
                    "decision_reason": request.reason,
                    "decided_at": self._now(),
                }
            )
        )
        execution_grant: ApprovalExecutionGrant | None = None
        grant_state: ApprovalExecutionGrantState | None = None
        if status == ApprovalStatus.APPROVED:
            grant_state, execution_grant = self._create_execution_grant(record)
        # The guarded decision and optional grant share one storage transaction.
        # A grant insert failure must roll the decision back to pending.
        self._storage.decide_with_grant_once(
            decided=decided,
            grant_state=grant_state,
        )
        return ApprovalDecisionResult(approval=decided, execution_grant=execution_grant)

    def _consume_execution_grant_via_storage(
        self,
        tenant_id: str,
        tool_call: ToolCallEnvelope,
    ) -> ApprovalRecord:
        assert self._storage is not None
        record = self._storage.get_record(tenant_id, tool_call.approval_id or "")
        if record is None or record.tenant_id != tenant_id:
            raise ApprovalNotFoundError("Approval was not found for this tenant.")
        if record.status != ApprovalStatus.APPROVED:
            raise ApprovalExecutionGrantError("Approval has not been approved.")
        # Atomic consume-once; storage raises the specific taxonomy error on 0 rows.
        self._storage.consume_grant_once(
            tenant_id=tenant_id,
            approval_id=tool_call.approval_id or "",
            token_hash=self._hash_execution_token(tool_call.approval_execution_token or ""),
            tool_call_fingerprint=self._tool_call_commitment(tool_call),
            now=self._now(),
        )
        return record

    def _load_from_storage(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        records: dict[str, ApprovalRecord] = {}
        grants: dict[str, ApprovalExecutionGrantState] = {}
        with self._storage_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    stored_record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(stored_record, Mapping):
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} must be a JSON object"
                    )
                record_type = stored_record.get("record_type")
                if record_type not in {"approval_record", "approval_execution_grant"}:
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} has unsupported record_type"
                    )
                payload = stored_record.get("payload")
                if not isinstance(payload, Mapping):
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} payload must be an object"
                    )
                if record_type == "approval_execution_grant":
                    grant_state = self._load_grant_state(payload, line_number)
                    grants[grant_state.approval_id] = grant_state
                    continue
                stored_payload = dict(payload)
                commitment = stored_payload.pop(TOOL_CALL_COMMITMENT_STORAGE_KEY, None)
                try:
                    approval = self._sanitize_record(ApprovalRecord.model_validate(stored_payload))
                except ValidationError as exc:
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} payload is invalid"
                    ) from exc
                _set_record_tool_call_commitment(approval, commitment)
                records[approval.approval_id] = approval
        self._records = records
        self._grants = grants

    def _append_record_locked(self, record: ApprovalRecord) -> None:
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        sanitized = self._sanitize_record(record)
        payload = sanitized.model_dump(mode="json")
        commitment = _record_tool_call_commitment(sanitized, required=False)
        if commitment is not None:
            payload[TOOL_CALL_COMMITMENT_STORAGE_KEY] = commitment
        stored_record = {
            "record_type": "approval_record",
            "payload": payload,
        }
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(stored_record, sort_keys=True, separators=(",", ":")) + "\n")

    def _append_grant_state_locked(self, state: ApprovalExecutionGrantState) -> None:
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        stored_record = {
            "record_type": "approval_execution_grant",
            "payload": {
                "approval_id": state.approval_id,
                "tenant_id": state.tenant_id,
                "tool_call_fingerprint": state.tool_call_fingerprint,
                "token_hash": state.token_hash,
                "expires_at": state.expires_at.isoformat(),
                "consumed_at": state.consumed_at.isoformat()
                if state.consumed_at is not None
                else None,
            },
        }
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(stored_record, sort_keys=True, separators=(",", ":")) + "\n")

    def _load_grant_state(
        self,
        payload: Mapping[object, object],
        line_number: int,
    ) -> ApprovalExecutionGrantState:
        try:
            approval_id = self._required_str(payload, "approval_id")
            tenant_id = self._required_str(payload, "tenant_id")
            fingerprint = self._required_str(payload, "tool_call_fingerprint")
            token_hash = self._required_str(payload, "token_hash")
            expires_at = self._parse_datetime(self._required_str(payload, "expires_at"))
            raw_consumed_at = payload.get("consumed_at")
            consumed_at = (
                self._parse_datetime(raw_consumed_at) if isinstance(raw_consumed_at, str) else None
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalQueueStorageError(
                f"Approval queue record {line_number} grant payload is invalid"
            ) from exc
        return ApprovalExecutionGrantState(
            approval_id=approval_id,
            tenant_id=tenant_id,
            tool_call_fingerprint=fingerprint,
            token_hash=token_hash,
            expires_at=expires_at,
            consumed_at=consumed_at,
        )

    def _sanitize_record(self, record: ApprovalRecord) -> ApprovalRecord:
        sanitized = record.model_copy(
            update={"tool_call": self._sanitize_tool_call(record.tool_call)},
            deep=True,
        )
        commitment = _record_tool_call_commitment(record, required=False)
        _set_record_tool_call_commitment(sanitized, commitment)
        return sanitized

    def _sanitize_tool_call(self, tool_call: ToolCallEnvelope) -> ToolCallEnvelope:
        return tool_call.model_copy(
            update={
                "input": self._redact_mapping(tool_call.input),
                "tool_schema": self._redact_mapping(tool_call.tool_schema),
                "caller_context": self._redact_mapping(tool_call.caller_context),
            }
        )

    def _redact_mapping(self, payload: Mapping[str, object]) -> dict[str, object]:
        return {key: self._redact_value(key, value) for key, value in payload.items()}

    def _redact_value(self, key: str, value: object) -> object:
        if SENSITIVE_KEY_RE.search(key):
            return REDACTED
        if isinstance(value, Mapping):
            return {
                nested_key: self._redact_value(str(nested_key), nested_value)
                for nested_key, nested_value in value.items()
            }
        if isinstance(value, list):
            return [self._redact_value(key, item) for item in value]
        return value

    def _create_execution_grant(
        self,
        record: ApprovalRecord,
    ) -> tuple[ApprovalExecutionGrantState, ApprovalExecutionGrant]:
        grant_value = secrets.token_urlsafe(32)
        expires_at = self._now() + self._execution_grant_ttl
        tool_call_commitment = _record_tool_call_commitment(record, required=True)
        if tool_call_commitment is None:  # pragma: no cover - required=True fails first
            raise ApprovalQueueStorageError(
                "Approval record is missing its original tool-call commitment."
            )
        if self._commitment_key is not None and not tool_call_commitment.startswith("hmac-sha256:"):
            raise ApprovalQueueStorageError(
                "A keyed approval queue cannot approve a legacy unkeyed tool-call commitment; request approval again."
            )
        state = ApprovalExecutionGrantState(
            approval_id=record.approval_id,
            tenant_id=record.tenant_id,
            tool_call_fingerprint=tool_call_commitment,
            token_hash=self._hash_execution_token(grant_value),
            expires_at=expires_at,
        )
        grant = ApprovalExecutionGrant(
            approval_id=record.approval_id,
            tenant_id=record.tenant_id,
            tool_name=record.tool_call.tool_name,
            execution_token=grant_value,
            expires_at=expires_at,
        )
        return state, grant

    def _tool_call_commitment(self, tool_call: ToolCallEnvelope) -> str:
        normalized = tool_call.model_copy(
            update={"approval_id": None, "approval_execution_token": None},
            deep=True,
        )
        payload = normalized.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        message = TOOL_CALL_COMMITMENT_DOMAIN + serialized.encode("utf-8")
        if self._commitment_key is not None:
            digest = hmac.new(self._commitment_key, message, hashlib.sha256).hexdigest()
            return f"hmac-sha256:{digest}"
        return f"sha256:{hashlib.sha256(message).hexdigest()}"

    def _hash_execution_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)

    def _required_str(self, payload: Mapping[object, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise KeyError(key)
        return value

    def _parse_datetime(self, value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)


def create_approval_queue(
    settings: Settings,
    *,
    sql_provider: SqlConnectionProvider | None = None,
    secret_manager: SecretManager | None = None,
    commitment_key: bytes | None = None,
) -> ApprovalQueue:
    backend = settings.approval_queue_backend.strip().lower()
    if settings.approval_execution_grant_ttl_seconds <= 0:
        raise ApprovalQueueConfigurationError(
            "Approval execution grant TTL must be a positive number of seconds."
        )
    environment = normalize_environment(settings.environment)
    if environment in {"production", "staging"} and backend not in {
        "postgres",
        "postgresql",
    }:
        raise ApprovalQueueConfigurationError(
            "Production and staging require the PostgreSQL approval queue backend for globally atomic decisions and single-use grants."
        )
    resolved_commitment_key = _resolve_commitment_key(
        settings,
        secret_manager=secret_manager,
        explicit_key=commitment_key,
    )
    if backend == "memory":
        return ApprovalQueue(
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds,
            commitment_key=resolved_commitment_key,
        )
    if backend == "jsonl":
        return ApprovalQueue(
            storage_path=settings.approval_queue_path,
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds,
            commitment_key=resolved_commitment_key,
        )
    if backend in {"postgres", "postgresql"}:
        if sql_provider is None:
            raise ApprovalQueueConfigurationError(
                "Postgres approval queue backend requires an injected SqlConnectionProvider."
            )
        return ApprovalQueue(
            storage=PostgresApprovalQueueStorage(connection=sql_provider),
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds,
            commitment_key=resolved_commitment_key,
        )
    raise ApprovalQueueConfigurationError(
        f"Unsupported approval queue backend: {settings.approval_queue_backend}"
    )


def _resolve_commitment_key(
    settings: Settings,
    *,
    secret_manager: SecretManager | None,
    explicit_key: bytes | None,
) -> bytes | None:
    environment = settings.environment.strip().lower()
    production_like = environment in {"production", "staging"}
    secret_name = settings.approval_tool_call_commitment_secret_name
    if production_like and explicit_key is not None:
        raise ApprovalQueueConfigurationError(
            "Production approval commitments must resolve a logical SecretManager name."
        )
    if secret_name is None or not secret_name.strip():
        if production_like:
            raise ApprovalQueueConfigurationError(
                "Production and staging require an approval commitment SecretManager name."
            )
        return explicit_key
    if explicit_key is not None:
        raise ApprovalQueueConfigurationError(
            "Configure either a logical approval commitment secret or an explicit local key."
        )
    if production_like and settings.secrets_backend.strip().lower() != "vault":
        raise ApprovalQueueConfigurationError(
            "Production approval commitments require the Vault SecretManager backend."
        )
    if secret_manager is None:
        raise ApprovalQueueConfigurationError(
            "Approval commitment secret resolution requires SecretManager."
        )
    try:
        secret_value = secret_manager.get_secret(secret_name.strip()).reveal()
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
        raise ApprovalQueueConfigurationError(
            "Approval commitment key could not be resolved from SecretManager."
        ) from None
    key = secret_value.encode("utf-8")
    if len(key) < MIN_COMMITMENT_KEY_BYTES:
        raise ApprovalQueueConfigurationError(
            "Approval commitment key from SecretManager must contain at least 32 bytes."
        )
    return key
