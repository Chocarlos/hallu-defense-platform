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
from typing import Callable
from uuid import uuid4

from pydantic import ValidationError

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    ApprovalDecision,
    ApprovalDecisionRequest,
    ApprovalExecutionGrant,
    ApprovalListRequest,
    ApprovalRecord,
    ApprovalStatus,
    ToolCallEnvelope,
)

SENSITIVE_KEY_RE = re.compile(r"(api[_-]?key|secret|token|password)", re.I)
REDACTED = "[REDACTED]"


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


class ApprovalQueue:
    def __init__(
        self,
        storage_path: Path | None = None,
        *,
        execution_grant_ttl_seconds: int = 900,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._storage_path = storage_path
        self._execution_grant_ttl = timedelta(seconds=execution_grant_ttl_seconds)
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
        with self._lock:
            self._append_record_locked(record)
            self._records[record.approval_id] = record
        return record

    def list_for_tenant(self, tenant_id: str, request: ApprovalListRequest) -> list[ApprovalRecord]:
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
            if grant_state.tool_call_fingerprint != self._tool_call_fingerprint(tool_call):
                raise ApprovalExecutionGrantError(
                    "Approval execution grant does not match this tool call."
                )

            consumed_state = replace(grant_state, consumed_at=self._now())
            self._append_grant_state_locked(consumed_state)
            self._grants[tool_call.approval_id] = consumed_state
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
                try:
                    approval = self._sanitize_record(ApprovalRecord.model_validate(payload))
                except ValidationError as exc:
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} payload is invalid"
                    ) from exc
                records[approval.approval_id] = approval
        self._records = records
        self._grants = grants

    def _append_record_locked(self, record: ApprovalRecord) -> None:
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        stored_record = {
            "record_type": "approval_record",
            "payload": self._sanitize_record(record).model_dump(mode="json"),
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
                self._parse_datetime(raw_consumed_at)
                if isinstance(raw_consumed_at, str)
                else None
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
        return record.model_copy(update={"tool_call": self._sanitize_tool_call(record.tool_call)}, deep=True)

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
        state = ApprovalExecutionGrantState(
            approval_id=record.approval_id,
            tenant_id=record.tenant_id,
            tool_call_fingerprint=self._tool_call_fingerprint(record.tool_call),
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

    def _tool_call_fingerprint(self, tool_call: ToolCallEnvelope) -> str:
        sanitized = self._sanitize_tool_call(tool_call)
        normalized = sanitized.model_copy(
            update={"approval_id": None, "approval_execution_token": None},
            deep=True,
        )
        payload = normalized.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

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


def create_approval_queue(settings: Settings) -> ApprovalQueue:
    backend = settings.approval_queue_backend.strip().lower()
    if settings.approval_execution_grant_ttl_seconds <= 0:
        raise ApprovalQueueConfigurationError(
            "Approval execution grant TTL must be a positive number of seconds."
        )
    if backend == "memory":
        if settings.environment.lower() in {"production", "staging"}:
            raise ApprovalQueueConfigurationError(
                "Production and staging must configure a persistent approval queue backend."
            )
        return ApprovalQueue(
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds
        )
    if backend == "jsonl":
        return ApprovalQueue(
            storage_path=settings.approval_queue_path,
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds,
        )
    raise ApprovalQueueConfigurationError(
        f"Unsupported approval queue backend: {settings.approval_queue_backend}"
    )
