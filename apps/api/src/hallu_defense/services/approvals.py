from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
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
from hallu_defense.services.content_security import REDACTED_SECRET, SensitiveDataRedactor
from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
)
from hallu_defense.services.tool_definitions import (
    ToolDefinitionError,
    TrustedToolRegistry,
    canonical_json_dumps,
    get_trusted_tool_binding,
)

REDACTED = REDACTED_SECRET
APPROVAL_BINDING_COMMITMENT_DOMAIN = b"hallu-defense:approval-binding:v3\x00"
# Compatibility name retained for the configuration integrity gate. The
# committed message is an ApprovalBinding, not a caller-provided envelope.
TOOL_CALL_COMMITMENT_DOMAIN = APPROVAL_BINDING_COMMITMENT_DOMAIN
APPROVAL_BINDING_COMMITMENT_STORAGE_KEY = "_hallu_approval_commitment_v3"
# Compatibility export retained for callers/tests while the persisted key is
# deliberately bumped. Records using the former value are rejected below.
TOOL_CALL_COMMITMENT_STORAGE_KEY = APPROVAL_BINDING_COMMITMENT_STORAGE_KEY
APPROVAL_BINDING_STORAGE_KEY = "_hallu_approval_binding_v3"
LEGACY_APPROVAL_STORAGE_KEYS = frozenset(
    {
        "_hallu_tool_call_commitment_v1",
        "_hallu_tool_call_commitment_v2",
        "_hallu_approval_commitment_v1",
        "_hallu_approval_commitment_v2",
        "_hallu_approval_binding_v1",
        "_hallu_approval_binding_v2",
    }
)
APPROVAL_BINDING_VERSION = "approval-binding.v3"
COMMITMENT_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
APPROVAL_COMMITMENT_RE = re.compile(
    r"^v3:(?:hmac-sha256:[A-Za-z0-9][A-Za-z0-9._-]{2,63}|"
    r"sha256:unkeyed-local):[0-9a-f]{64}$"
)
TOOL_DEFINITION_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ARGUMENTS_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MIN_COMMITMENT_KEY_BYTES = 32
MAX_COMMITMENT_ROTATION_OVERLAP = timedelta(days=7)


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


class ApprovalPayloadSanitizationError(ApprovalError):
    """Raised when sensitive approval data cannot be redacted completely."""


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


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    """The exact authorization facts reviewed by a human approver."""

    schema_version: str
    approval_id: str
    origin_trace_id: str
    tenant_id: str
    subject_id: str
    environment: str
    tool_name: str
    policy_action: str
    arguments_hash: str
    definition_version: str
    definition_digest: str
    commitment_algorithm: str
    commitment_key_id: str

    def as_payload(self) -> dict[str, str]:
        return {
            "approval_id": self.approval_id,
            "arguments_hash": self.arguments_hash,
            "commitment_algorithm": self.commitment_algorithm,
            "commitment_key_id": self.commitment_key_id,
            "definition_digest": self.definition_digest,
            "definition_version": self.definition_version,
            "environment": self.environment,
            "origin_trace_id": self.origin_trace_id,
            "policy_action": self.policy_action,
            "schema_version": self.schema_version,
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "tool_name": self.tool_name,
        }

    @classmethod
    def from_payload(cls, value: object) -> ApprovalBinding:
        if not isinstance(value, Mapping):
            raise ApprovalQueueStorageError("Approval binding must be an object.")
        expected_keys = {
            "approval_id",
            "arguments_hash",
            "commitment_algorithm",
            "commitment_key_id",
            "definition_digest",
            "definition_version",
            "environment",
            "origin_trace_id",
            "policy_action",
            "schema_version",
            "subject_id",
            "tenant_id",
            "tool_name",
        }
        if set(value) != expected_keys:
            raise ApprovalQueueStorageError("Approval binding has invalid fields.")
        payload: dict[str, str] = {}
        for key in expected_keys:
            item = value.get(key)
            if not isinstance(item, str) or not item:
                raise ApprovalQueueStorageError("Approval binding contains an invalid value.")
            payload[key] = item
        if ARGUMENTS_HASH_RE.fullmatch(payload["arguments_hash"]) is None:
            raise ApprovalQueueStorageError("Approval binding arguments hash is invalid.")
        if TOOL_DEFINITION_DIGEST_RE.fullmatch(payload["definition_digest"]) is None:
            raise ApprovalQueueStorageError("Approval binding definition digest is invalid.")
        if payload["schema_version"] != APPROVAL_BINDING_VERSION:
            raise ApprovalQueueStorageError("Approval binding version is unsupported.")
        try:
            payload["environment"] = normalize_environment(payload["environment"])
        except ValueError as exc:
            raise ApprovalQueueStorageError("Approval binding environment is invalid.") from exc
        algorithm = payload["commitment_algorithm"]
        key_id = payload["commitment_key_id"]
        if algorithm == "hmac-sha256":
            if COMMITMENT_KEY_ID_RE.fullmatch(key_id) is None:
                raise ApprovalQueueStorageError("Approval binding key identifier is invalid.")
        elif algorithm == "sha256":
            if key_id != "unkeyed-local":
                raise ApprovalQueueStorageError("Approval binding key identifier is invalid.")
        else:
            raise ApprovalQueueStorageError("Approval binding algorithm is unsupported.")
        for key in ("approval_id", "origin_trace_id", "tenant_id", "subject_id"):
            identity = payload[key]
            if (
                identity != identity.strip()
                or len(identity) > 256
                or any(
                    unicodedata.category(character) in {"Cc", "Cf"}
                    for character in identity
                )
            ):
                raise ApprovalQueueStorageError("Approval binding identity is invalid.")
        for key in ("tool_name", "policy_action", "definition_version"):
            if len(payload[key]) > 128:
                raise ApprovalQueueStorageError("Approval binding metadata is too long.")
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class ConsumedApprovalAuthorization:
    """In-process capability emitted only after an atomic grant consume."""

    approval_id: str
    binding: ApprovalBinding
    _issuer_token: object = field(repr=False, compare=False)
    _capability_token: object = field(repr=False, compare=False)


class ApprovalAuthorizationIssuer:
    """Issues process-local, identity-checked approval capabilities."""

    __slots__ = ("_active_capabilities", "_issuer_token", "_lock")

    def __init__(self) -> None:
        self._issuer_token = object()
        self._active_capabilities: set[object] = set()
        self._lock = threading.Lock()

    def issue(
        self,
        *,
        approval_id: str,
        binding: ApprovalBinding,
    ) -> ConsumedApprovalAuthorization:
        capability_token = object()
        with self._lock:
            self._active_capabilities.add(capability_token)
        return ConsumedApprovalAuthorization(
            approval_id=approval_id,
            binding=binding,
            _issuer_token=self._issuer_token,
            _capability_token=capability_token,
        )

    def consume(self, authorization: object) -> bool:
        if (
            not isinstance(authorization, ConsumedApprovalAuthorization)
            or authorization._issuer_token is not self._issuer_token
        ):
            return False
        with self._lock:
            if authorization._capability_token not in self._active_capabilities:
                return False
            self._active_capabilities.remove(authorization._capability_token)
        return True


def _set_record_tool_call_commitment(
    record: ApprovalRecord,
    commitment: object,
) -> None:
    if commitment is None:
        record._tool_call_commitment = None
        return
    if not isinstance(commitment, str) or APPROVAL_COMMITMENT_RE.fullmatch(commitment) is None:
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
    if APPROVAL_COMMITMENT_RE.fullmatch(commitment) is None:
        raise ApprovalQueueStorageError("Approval record tool-call commitment is invalid.")
    return commitment


def _set_record_approval_binding(
    record: ApprovalRecord,
    binding: object,
) -> None:
    if binding is None:
        record._approval_binding = None
        return
    if isinstance(binding, Mapping):
        binding = ApprovalBinding.from_payload(binding)
    if not isinstance(binding, ApprovalBinding):
        raise ApprovalQueueStorageError("Approval record binding is invalid.")
    record._approval_binding = binding


def _record_approval_binding(
    record: ApprovalRecord,
    *,
    required: bool,
) -> ApprovalBinding | None:
    binding = record._approval_binding
    if binding is None:
        if required:
            raise ApprovalQueueStorageError(
                "Approval record is missing its trusted authorization binding."
            )
        return None
    if not isinstance(binding, ApprovalBinding):
        raise ApprovalQueueStorageError("Approval record binding is invalid.")
    return binding


def _copy_record_private_metadata(source: ApprovalRecord, target: ApprovalRecord) -> None:
    _set_record_tool_call_commitment(
        target,
        _record_tool_call_commitment(source, required=False),
    )
    _set_record_approval_binding(
        target,
        _record_approval_binding(source, required=False),
    )


def _pop_private_approval_metadata(
    payload: dict[str, object],
) -> tuple[object, object]:
    legacy = sorted(LEGACY_APPROVAL_STORAGE_KEYS.intersection(payload))
    if legacy:
        raise ApprovalQueueStorageError(
            "Legacy or provisional approval commitment storage is unsupported; "
            "request approval again."
        )
    commitment = payload.pop(APPROVAL_BINDING_COMMITMENT_STORAGE_KEY, None)
    binding = payload.pop(APPROVAL_BINDING_STORAGE_KEY, None)
    return commitment, binding


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
        binding = _record_approval_binding(record, required=False)
        if binding is not None:
            payload[APPROVAL_BINDING_STORAGE_KEY] = binding.as_payload()
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
        commitment, binding = _pop_private_approval_metadata(stored_payload)
        try:
            record = ApprovalRecord.model_validate(stored_payload)
        except ValidationError as exc:
            raise ApprovalQueueStorageError(
                f"Postgres approval record {row_number} payload is invalid"
            ) from exc
        _set_record_tool_call_commitment(record, commitment)
        _set_record_approval_binding(record, binding)
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
        commitment_key_id: str | None = None,
        previous_commitment_keys: Sequence[bytes] = (),
        previous_commitment_key_ids: Sequence[str] = (),
        previous_commitment_keys_valid_until: datetime | None = None,
        commitment_environment: str = "local",
        tool_registry: TrustedToolRegistry | None = None,
        redactor: SensitiveDataRedactor | None = None,
        authorization_issuer: ApprovalAuthorizationIssuer | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if storage_path is not None and storage is not None:
            raise ApprovalQueueConfigurationError(
                "Configure either storage_path or storage, not both."
            )
        self._storage_path = storage_path
        self._storage = storage
        self._execution_grant_ttl = timedelta(seconds=execution_grant_ttl_seconds)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        try:
            self._commitment_environment = normalize_environment(commitment_environment)
        except ValueError as exc:
            raise ApprovalQueueConfigurationError(
                "Approval commitment environment is invalid."
            ) from exc
        self._validate_commitment_key(commitment_key)
        if self._commitment_environment in {"production", "staging"} and commitment_key is None:
            raise ApprovalQueueConfigurationError(
                "Production and staging approval commitments require an HMAC key."
            )
        if commitment_key is None:
            if commitment_key_id is not None:
                raise ApprovalQueueConfigurationError(
                    "An approval commitment key identifier requires an active key."
                )
            active_key_id: str | None = None
        else:
            if commitment_key_id is None:
                if self._commitment_environment in {"production", "staging"}:
                    raise ApprovalQueueConfigurationError(
                        "Production and staging require an explicit opaque approval commitment key identifier."
                    )
                active_key_id = "local-active"
            else:
                active_key_id = self._validate_commitment_key_id(commitment_key_id)
        previous_keys = tuple(previous_commitment_keys)
        previous_key_ids = tuple(previous_commitment_key_ids)
        if len(previous_keys) > 1:
            raise ApprovalQueueConfigurationError(
                "Approval commitment rotation supports exactly one previous key."
            )
        for previous_key in previous_keys:
            self._validate_commitment_key(previous_key)
        if commitment_key is None and previous_keys:
            raise ApprovalQueueConfigurationError(
                "Previous approval commitment keys require an active commitment key."
            )
        if previous_keys and commitment_key_id is None:
            raise ApprovalQueueConfigurationError(
                "Approval commitment rotation requires an explicit opaque active key identifier."
            )
        if previous_keys and not previous_key_ids:
            raise ApprovalQueueConfigurationError(
                "Approval commitment rotation requires an explicit opaque previous key identifier."
            )
        if len(previous_key_ids) != len(previous_keys):
            raise ApprovalQueueConfigurationError(
                "Previous approval commitment keys and key identifiers must match."
            )
        previous_key_ids = tuple(
            self._validate_commitment_key_id(key_id) for key_id in previous_key_ids
        )
        if (
            commitment_key is not None
            and previous_keys
            and hmac.compare_digest(commitment_key, previous_keys[0])
        ):
            raise ApprovalQueueConfigurationError(
                "Active and previous approval commitment keys must be distinct."
            )
        if previous_keys:
            if previous_commitment_keys_valid_until is None:
                raise ApprovalQueueConfigurationError(
                    "Previous approval commitment keys require a bounded valid-until timestamp."
                )
            valid_until = self._normalize_rotation_deadline(
                previous_commitment_keys_valid_until
            )
            now = self._now()
            if valid_until <= now:
                raise ApprovalQueueConfigurationError(
                    "Previous approval commitment key overlap has already expired."
                )
            if valid_until > now + MAX_COMMITMENT_ROTATION_OVERLAP:
                raise ApprovalQueueConfigurationError(
                    "Previous approval commitment key overlap cannot exceed seven days."
                )
            self._previous_commitment_keys_valid_until: datetime | None = valid_until
        else:
            if previous_commitment_keys_valid_until is not None:
                raise ApprovalQueueConfigurationError(
                    "A previous-key valid-until timestamp requires a previous commitment key."
                )
            self._previous_commitment_keys_valid_until = None
        self._commitment_key = commitment_key
        self._active_commitment_key_id = active_key_id
        all_commitment_keys = tuple(
            key for key in (commitment_key, *previous_keys) if key is not None
        )
        key_ids = tuple(
            key_id
            for key_id in (active_key_id, *previous_key_ids)
            if key_id is not None
        )
        if len(set(key_ids)) != len(key_ids):
            raise ApprovalQueueConfigurationError(
                "Approval commitment rotation keys must be distinct."
            )
        self._commitment_keys_by_id = dict(
            zip(key_ids, all_commitment_keys, strict=True)
        )
        self._tool_registry = tool_registry or TrustedToolRegistry.default()
        self._redactor = redactor or SensitiveDataRedactor()
        self._authorization_issuer = authorization_issuer or ApprovalAuthorizationIssuer()
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
        canonical_tool_call = self._bind_tool_call(tool_call)
        trusted_binding = get_trusted_tool_binding(canonical_tool_call)
        if not trusted_binding.approval_required:
            raise ToolDefinitionError(
                "Trusted tool definition does not require a human approval."
            )
        self._require_matching_tenant(canonical_tool_call, tenant_id)
        verified_context = dict(canonical_tool_call.caller_context)
        verified_context["tenant_id"] = tenant_id
        verified_context["subject"] = requested_by
        canonical_tool_call = canonical_tool_call.model_copy(
            update={"caller_context": verified_context},
            deep=True,
        )
        canonical_tool_call._trusted_definition = trusted_binding
        subject_id = self._resolve_subject(
            canonical_tool_call,
            asserted_subject=requested_by,
        )
        # The record identity is part of the authorization domain. Generate it
        # before deriving the commitment so two otherwise identical reviews
        # can never substitute for one another.
        approval_id = f"apr_{uuid4().hex}"
        binding = self._approval_binding(
            approval_id=approval_id,
            origin_trace_id=trace_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            tool_call=canonical_tool_call,
        )
        commitment = self._binding_commitment(binding)
        sanitized_tool_call = self._sanitize_tool_call(canonical_tool_call)
        sanitized_reason = self._sanitize_text(reason, field="approval reason")
        record = ApprovalRecord(
            approval_id=approval_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            tool_call=sanitized_tool_call,
            status=ApprovalStatus.PENDING,
            risk_level=canonical_tool_call.risk_level,
            reason=sanitized_reason,
            requested_by=requested_by,
        )
        _set_record_tool_call_commitment(record, commitment)
        _set_record_approval_binding(record, binding)
        if self._storage is not None:
            self._storage.insert_record(record)
            return record
        with self._lock:
            self._append_record_locked(record)
            self._records[record.approval_id] = record
        return record

    def list_for_tenant(self, tenant_id: str, request: ApprovalListRequest) -> list[ApprovalRecord]:
        if self._storage is not None:
            records = [
                self._sanitize_record(record)
                for record in self._storage.list_records(tenant_id)
            ]
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
            sanitized_decision_reason = self._sanitize_text(
                request.reason,
                field="approval decision reason",
            )

            status = (
                ApprovalStatus.APPROVED
                if request.decision == ApprovalDecision.APPROVE
                else ApprovalStatus.REJECTED
            )
            decided = record.model_copy(
                update={
                    "status": status,
                    "decided_by": request.decided_by,
                    "decision_reason": sanitized_decision_reason,
                    "decided_at": self._now(),
                }
            )
            _copy_record_private_metadata(record, decided)
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
        *,
        subject_id: str,
    ) -> ConsumedApprovalAuthorization:
        try:
            canonical_tool_call = self._bind_tool_call(tool_call)
            self._require_matching_tenant(canonical_tool_call, tenant_id)
            resolved_subject = self._resolve_subject(
                canonical_tool_call,
                asserted_subject=subject_id,
            )
        except ToolDefinitionError as exc:
            raise ApprovalExecutionGrantError(
                "Approval execution grant does not match a trusted tool definition."
            ) from exc
        tool_call = canonical_tool_call
        if not tool_call.approval_id or not tool_call.approval_execution_token:
            raise ApprovalExecutionGrantError("Approval execution grant is required.")
        if self._storage is not None:
            try:
                stored_record, binding = self._consume_execution_grant_via_storage(
                    tenant_id,
                    resolved_subject,
                    tool_call,
                )
            except ApprovalQueueStorageError as exc:
                raise ApprovalExecutionGrantError(
                    "Approval execution grant does not match this tool call."
                ) from exc
            return self._consumed_authorization(stored_record, binding)
        with self._lock:
            record = self._records.get(tool_call.approval_id)
            if record is None or record.tenant_id != tenant_id:
                raise ApprovalNotFoundError("Approval was not found for this tenant.")
            if record.status != ApprovalStatus.APPROVED:
                raise ApprovalExecutionGrantError("Approval has not been approved.")

            try:
                stored_binding = self._validated_record_binding(record)
            except ApprovalQueueStorageError as exc:
                raise ApprovalExecutionGrantError(
                    "Approval execution grant does not match this tool call."
                ) from exc
            requested_binding = self._approval_binding(
                approval_id=record.approval_id,
                origin_trace_id=record.trace_id,
                tenant_id=tenant_id,
                subject_id=resolved_subject,
                tool_call=tool_call,
                commitment_algorithm=stored_binding.commitment_algorithm,
                commitment_key_id=stored_binding.commitment_key_id,
            )
            if stored_binding != requested_binding:
                raise ApprovalExecutionGrantError(
                    "Approval execution grant does not match this tool call."
                )

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
                self._binding_commitment(stored_binding),
            ):
                raise ApprovalExecutionGrantError(
                    "Approval execution grant does not match this tool call."
                )

            consumed_state = replace(grant_state, consumed_at=self._now())
            self._append_grant_state_locked(consumed_state)
            self._grants[tool_call.approval_id] = consumed_state
            return self._consumed_authorization(record, stored_binding)

    def _decide_with_grant_via_storage(
        self,
        tenant_id: str,
        request: ApprovalDecisionRequest,
    ) -> ApprovalDecisionResult:
        assert self._storage is not None
        record = self._storage.get_record(tenant_id, request.approval_id)
        if record is None or record.tenant_id != tenant_id:
            raise ApprovalNotFoundError("Approval was not found for this tenant.")
        record = self._sanitize_record(record)
        if record.status != ApprovalStatus.PENDING:
            raise ApprovalAlreadyDecidedError("Approval has already been decided.")
        if not request.decided_by:
            raise ApprovalDecisionIdentityError("Approval decision requires reviewer identity.")
        sanitized_decision_reason = self._sanitize_text(
            request.reason,
            field="approval decision reason",
        )

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
                    "decision_reason": sanitized_decision_reason,
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
        subject_id: str,
        tool_call: ToolCallEnvelope,
    ) -> tuple[ApprovalRecord, ApprovalBinding]:
        assert self._storage is not None
        record = self._storage.get_record(tenant_id, tool_call.approval_id or "")
        if record is None or record.tenant_id != tenant_id:
            raise ApprovalNotFoundError("Approval was not found for this tenant.")
        record = self._sanitize_record(record)
        if record.status != ApprovalStatus.APPROVED:
            raise ApprovalExecutionGrantError("Approval has not been approved.")
        stored_binding = self._validated_record_binding(record)
        requested_binding = self._approval_binding(
            approval_id=record.approval_id,
            origin_trace_id=record.trace_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            tool_call=tool_call,
            commitment_algorithm=stored_binding.commitment_algorithm,
            commitment_key_id=stored_binding.commitment_key_id,
        )
        if stored_binding != requested_binding:
            raise ApprovalExecutionGrantError(
                "Approval execution grant does not match this tool call."
            )
        # Atomic consume-once; storage raises the specific taxonomy error on 0 rows.
        self._storage.consume_grant_once(
            tenant_id=tenant_id,
            approval_id=tool_call.approval_id or "",
            token_hash=self._hash_execution_token(tool_call.approval_execution_token or ""),
            tool_call_fingerprint=self._binding_commitment(stored_binding),
            now=self._now(),
        )
        return record, stored_binding

    def _consumed_authorization(
        self,
        record: ApprovalRecord,
        binding: ApprovalBinding,
    ) -> ConsumedApprovalAuthorization:
        return self._authorization_issuer.issue(
            approval_id=record.approval_id,
            binding=binding,
        )

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
                commitment, binding = _pop_private_approval_metadata(stored_payload)
                try:
                    approval = self._sanitize_record(ApprovalRecord.model_validate(stored_payload))
                except (ValidationError, ApprovalPayloadSanitizationError) as exc:
                    raise ApprovalQueueStorageError(
                        f"Approval queue record {line_number} payload is invalid"
                    ) from exc
                _set_record_tool_call_commitment(approval, commitment)
                _set_record_approval_binding(approval, binding)
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
        binding = _record_approval_binding(sanitized, required=False)
        if binding is not None:
            payload[APPROVAL_BINDING_STORAGE_KEY] = binding.as_payload()
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
        sanitized_tool_call = self._sanitize_tool_call(record.tool_call)
        sanitized_reason = self._sanitize_text(record.reason, field="approval reason")
        sanitized_decision_reason = (
            self._sanitize_text(
                record.decision_reason,
                field="approval decision reason",
            )
            if record.decision_reason is not None
            else None
        )
        sanitized = record.model_copy(
            update={
                "tool_call": sanitized_tool_call,
                "reason": sanitized_reason,
                "decision_reason": sanitized_decision_reason,
            },
            deep=True,
        )
        _copy_record_private_metadata(record, sanitized)
        return sanitized

    def _sanitize_tool_call(self, tool_call: ToolCallEnvelope) -> ToolCallEnvelope:
        result = self._redactor.redact(
            {
                "input": tool_call.input,
                "schema": tool_call.tool_schema,
                "caller_context": tool_call.caller_context,
            }
        )
        if not result.complete:
            joined = ", ".join(result.violations) or "unknown traversal failure"
            raise ApprovalPayloadSanitizationError(
                f"Approval tool payload could not be redacted completely: {joined}."
            )
        if not isinstance(result.value, Mapping):  # pragma: no cover - fixed wrapper
            raise ApprovalPayloadSanitizationError(
                "Approval tool payload redaction returned an invalid structure."
            )
        redacted_input = result.value.get("input")
        redacted_schema = result.value.get("schema")
        redacted_context = result.value.get("caller_context")
        if (
            not isinstance(redacted_input, Mapping)
            or not isinstance(redacted_schema, Mapping)
            or not isinstance(redacted_context, Mapping)
        ):
            raise ApprovalPayloadSanitizationError(
                "Approval tool payload redaction did not preserve object fields."
            )
        sanitized = tool_call.model_copy(
            update={
                "input": dict(redacted_input),
                "tool_schema": dict(redacted_schema),
                "caller_context": dict(redacted_context),
            }
        )
        try:
            sanitized._trusted_definition = get_trusted_tool_binding(tool_call)
        except ToolDefinitionError:
            # Persisted public snapshots intentionally do not serialize private
            # registry bindings. The separately persisted ApprovalBinding is
            # the authorization source of truth after reload.
            sanitized._trusted_definition = None
        return sanitized

    def _sanitize_text(self, value: str, *, field: str) -> str:
        result = self._redactor.redact_text(value)
        if not result.complete or not isinstance(result.value, str):
            joined = ", ".join(result.violations) or "invalid redaction result"
            raise ApprovalPayloadSanitizationError(
                f"{field.capitalize()} could not be redacted completely: {joined}."
            )
        return result.value

    def _create_execution_grant(
        self,
        record: ApprovalRecord,
    ) -> tuple[ApprovalExecutionGrantState, ApprovalExecutionGrant]:
        grant_value = secrets.token_urlsafe(32)
        expires_at = self._now() + self._execution_grant_ttl
        binding = self._validated_record_binding(record)
        if (
            binding.commitment_algorithm == "hmac-sha256"
            and binding.commitment_key_id != self._active_commitment_key_id
        ):
            valid_until = self._previous_commitment_keys_valid_until
            if valid_until is None or expires_at > valid_until:
                raise ApprovalQueueStorageError(
                    "Approval grant would outlive the previous commitment key overlap; "
                    "request approval again."
                )
        tool_call_commitment = _record_tool_call_commitment(record, required=True)
        if tool_call_commitment is None:  # pragma: no cover - required=True fails first
            raise ApprovalQueueStorageError(
                "Approval record is missing its original tool-call commitment."
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

    def _validated_record_binding(self, record: ApprovalRecord) -> ApprovalBinding:
        """Validate persisted review facts before issuing or consuming authority."""

        tool_call_commitment = _record_tool_call_commitment(record, required=True)
        if tool_call_commitment is None:  # pragma: no cover - required=True raises first
            raise ApprovalQueueStorageError(
                "Approval record is missing its original tool-call commitment."
            )
        binding = _record_approval_binding(record, required=True)
        if binding is None:  # pragma: no cover - required=True raises first
            raise ApprovalQueueStorageError(
                "Approval record is missing its trusted authorization binding."
            )
        try:
            current_definition = self._tool_registry.resolve(binding.tool_name)
        except ToolDefinitionError as exc:
            raise ApprovalQueueStorageError(
                "Approval references a tool definition that is no longer trusted."
            ) from exc
        if current_definition.binding().definition_digest != binding.definition_digest:
            raise ApprovalQueueStorageError(
                "Approval references a stale tool definition; request approval again."
            )
        if not current_definition.approval_required:
            raise ApprovalQueueStorageError(
                "Approval references a definition that does not require approval."
            )
        if (
            record.approval_id != binding.approval_id
            or record.trace_id != binding.origin_trace_id
            or record.tenant_id != binding.tenant_id
            or record.requested_by != binding.subject_id
            or binding.environment != self._commitment_environment
            or record.tool_call.tool_name != binding.tool_name
            or record.risk_level is not current_definition.risk_level
            or record.tool_call.risk_level is not current_definition.risk_level
            or record.tool_call.approval_required is not current_definition.approval_required
            or record.tool_call.caller_context.get("tenant_id") != binding.tenant_id
            or record.tool_call.caller_context.get("subject") != binding.subject_id
            or binding.policy_action != current_definition.policy_action
            or binding.definition_version != current_definition.version
        ):
            raise ApprovalQueueStorageError(
                "Approval record does not match its trusted authorization binding."
            )
        if not hmac.compare_digest(
            tool_call_commitment,
            self._binding_commitment(binding),
        ):
            raise ApprovalQueueStorageError("Approval authorization binding is inconsistent.")
        return binding

    def _binding_commitment(self, binding: ApprovalBinding) -> str:
        serialized = canonical_json_dumps(binding.as_payload())
        message = APPROVAL_BINDING_COMMITMENT_DOMAIN + serialized.encode("utf-8")
        if binding.commitment_algorithm == "hmac-sha256":
            key = self._verification_key(binding.commitment_key_id)
            if key is None:
                raise ApprovalQueueStorageError(
                    "Approval binding uses an unknown or expired commitment key; "
                    "request approval again."
                )
            digest = hmac.new(key, message, hashlib.sha256).hexdigest()
        elif (
            binding.commitment_algorithm == "sha256"
            and binding.commitment_key_id == "unkeyed-local"
            and self._commitment_key is None
        ):
            digest = hashlib.sha256(message).hexdigest()
        elif binding.commitment_algorithm == "sha256" and self._commitment_key is not None:
            raise ApprovalQueueStorageError(
                "A keyed approval queue cannot approve a legacy unkeyed commitment; "
                "request approval again."
            )
        else:
            raise ApprovalQueueStorageError(
                "Approval binding commitment mode is incompatible with this queue; "
                "request approval again."
            )
        return (
            f"v3:{binding.commitment_algorithm}:"
            f"{binding.commitment_key_id}:{digest}"
        )

    def _tool_call_commitment(
        self,
        tool_call: ToolCallEnvelope,
        *,
        approval_id: str,
        origin_trace_id: str,
        tenant_id: str,
        subject_id: str,
    ) -> str:
        """Compatibility helper; new code should commit an explicit binding."""

        canonical_tool_call = self._bind_tool_call(tool_call)
        self._require_matching_tenant(canonical_tool_call, tenant_id)
        resolved_subject = self._resolve_subject(canonical_tool_call, asserted_subject=subject_id)
        return self._binding_commitment(
            self._approval_binding(
                approval_id=approval_id,
                origin_trace_id=origin_trace_id,
                tenant_id=tenant_id,
                subject_id=resolved_subject,
                tool_call=canonical_tool_call,
            )
        )

    def _bind_tool_call(self, tool_call: ToolCallEnvelope) -> ToolCallEnvelope:
        canonical = self._tool_registry.bind(tool_call, phase="input")
        self._tool_registry.verify_binding(canonical)
        return canonical

    def _approval_binding(
        self,
        *,
        approval_id: str,
        origin_trace_id: str,
        tenant_id: str,
        subject_id: str,
        tool_call: ToolCallEnvelope,
        commitment_algorithm: str | None = None,
        commitment_key_id: str | None = None,
    ) -> ApprovalBinding:
        trusted = self._tool_registry.verify_binding(tool_call)
        arguments_hash = "sha256:" + hashlib.sha256(
            canonical_json_dumps(tool_call.input).encode("utf-8")
        ).hexdigest()
        return ApprovalBinding(
            schema_version=APPROVAL_BINDING_VERSION,
            approval_id=self._validated_identity(approval_id, "identifier"),
            origin_trace_id=self._validated_identity(origin_trace_id, "origin trace"),
            tenant_id=tenant_id,
            subject_id=subject_id,
            environment=self._commitment_environment,
            tool_name=trusted.tool_name,
            policy_action=trusted.policy_action,
            arguments_hash=arguments_hash,
            definition_version=trusted.definition_version,
            definition_digest=trusted.definition_digest,
            commitment_algorithm=(
                commitment_algorithm
                or ("hmac-sha256" if self._commitment_key is not None else "sha256")
            ),
            commitment_key_id=(
                commitment_key_id
                or self._active_commitment_key_id
                or "unkeyed-local"
            ),
        )

    def _verification_key(self, key_id: str) -> bytes | None:
        key = self._commitment_keys_by_id.get(key_id)
        if key is None:
            return None
        if key_id == self._active_commitment_key_id:
            return key
        valid_until = self._previous_commitment_keys_valid_until
        if valid_until is None or self._now() >= valid_until:
            return None
        return key

    @staticmethod
    def _normalize_rotation_deadline(value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ApprovalQueueConfigurationError(
                "Previous-key valid-until timestamp must include a timezone."
            )
        return value.astimezone(timezone.utc)

    @staticmethod
    def _validate_commitment_key_id(key_id: str) -> str:
        if COMMITMENT_KEY_ID_RE.fullmatch(key_id) is None:
            raise ApprovalQueueConfigurationError(
                "Approval commitment key identifiers must be opaque 3-64 character labels."
            )
        return key_id

    @staticmethod
    def _validate_commitment_key(key: bytes | None) -> None:
        if key is not None and (
            not isinstance(key, bytes) or len(key) < MIN_COMMITMENT_KEY_BYTES
        ):
            raise ApprovalQueueConfigurationError(
                "Approval tool-call commitment key must contain at least 32 bytes."
            )

    def _resolve_subject(
        self,
        tool_call: ToolCallEnvelope,
        *,
        asserted_subject: str | None = None,
    ) -> str:
        context_subject = self._context_identity(tool_call, "subject")
        if asserted_subject is not None:
            return self._validated_identity(asserted_subject, "subject")
        if context_subject is None:
            raise ToolDefinitionError("Approval requires a verified subject identity.")
        return context_subject

    def _require_matching_tenant(
        self,
        tool_call: ToolCallEnvelope,
        tenant_id: str,
    ) -> None:
        tenant_id = self._validated_identity(tenant_id, "tenant")
        context_tenant = self._context_identity(tool_call, "tenant_id")
        if context_tenant is not None and context_tenant != tenant_id:
            raise ToolDefinitionError(
                "Tool caller_context tenant does not match the authenticated tenant."
            )

    def _context_identity(self, tool_call: ToolCallEnvelope, key: str) -> str | None:
        value = tool_call.caller_context.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ToolDefinitionError(f"Tool caller_context {key} is invalid.")
        return self._validated_identity(value, key)

    def _validated_identity(self, value: str, label: str) -> str:
        if (
            not value
            or value != value.strip()
            or len(value) > 256
            or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
        ):
            raise ToolDefinitionError(f"Approval {label} identity is invalid.")
        return value

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
    tool_registry: TrustedToolRegistry | None = None,
    redactor: SensitiveDataRedactor | None = None,
    authorization_issuer: ApprovalAuthorizationIssuer | None = None,
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
    resolved_commitment_key, previous_commitment_keys = _resolve_commitment_keys(
        settings,
        secret_manager=secret_manager,
        explicit_key=commitment_key,
    )
    previous_keys_valid_until = _parse_commitment_rotation_deadline(
        settings.approval_tool_call_commitment_previous_valid_until
    )
    previous_key_ids = (
        (settings.approval_tool_call_commitment_previous_key_id,)
        if settings.approval_tool_call_commitment_previous_key_id is not None
        else ()
    )
    if backend == "memory":
        return ApprovalQueue(
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds,
            commitment_key=resolved_commitment_key,
            commitment_key_id=settings.approval_tool_call_commitment_key_id,
            previous_commitment_keys=previous_commitment_keys,
            previous_commitment_key_ids=previous_key_ids,
            previous_commitment_keys_valid_until=previous_keys_valid_until,
            commitment_environment=environment,
            tool_registry=tool_registry,
            redactor=redactor,
            authorization_issuer=authorization_issuer,
        )
    if backend == "jsonl":
        return ApprovalQueue(
            storage_path=settings.approval_queue_path,
            execution_grant_ttl_seconds=settings.approval_execution_grant_ttl_seconds,
            commitment_key=resolved_commitment_key,
            commitment_key_id=settings.approval_tool_call_commitment_key_id,
            previous_commitment_keys=previous_commitment_keys,
            previous_commitment_key_ids=previous_key_ids,
            previous_commitment_keys_valid_until=previous_keys_valid_until,
            commitment_environment=environment,
            tool_registry=tool_registry,
            redactor=redactor,
            authorization_issuer=authorization_issuer,
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
            commitment_key_id=settings.approval_tool_call_commitment_key_id,
            previous_commitment_keys=previous_commitment_keys,
            previous_commitment_key_ids=previous_key_ids,
            previous_commitment_keys_valid_until=previous_keys_valid_until,
            commitment_environment=environment,
            tool_registry=tool_registry,
            redactor=redactor,
            authorization_issuer=authorization_issuer,
        )
    raise ApprovalQueueConfigurationError(
        f"Unsupported approval queue backend: {settings.approval_queue_backend}"
    )


def _resolve_commitment_keys(
    settings: Settings,
    *,
    secret_manager: SecretManager | None,
    explicit_key: bytes | None,
) -> tuple[bytes | None, tuple[bytes, ...]]:
    environment = settings.environment.strip().lower()
    production_like = environment in {"production", "staging"}
    secret_name = settings.approval_tool_call_commitment_secret_name
    previous_secret_name = settings.approval_tool_call_commitment_previous_secret_name
    if production_like and explicit_key is not None:
        raise ApprovalQueueConfigurationError(
            "Production approval commitments must resolve a logical SecretManager name."
        )
    if secret_name is None or not secret_name.strip():
        if production_like:
            raise ApprovalQueueConfigurationError(
                "Production and staging require an approval commitment SecretManager name."
            )
        if previous_secret_name is not None and previous_secret_name.strip():
            raise ApprovalQueueConfigurationError(
                "A previous approval commitment secret requires an active logical secret."
            )
        return explicit_key, ()
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
    active_name = secret_name.strip()
    previous_name = (
        previous_secret_name.strip()
        if previous_secret_name is not None
        else ""
    )
    if previous_name and previous_name == active_name:
        raise ApprovalQueueConfigurationError(
            "Active and previous approval commitment secret names must differ."
        )
    key = _load_commitment_key(secret_manager, active_name, role="active")
    previous_keys = (
        (_load_commitment_key(secret_manager, previous_name, role="previous"),)
        if previous_name
        else ()
    )
    if previous_keys and hmac.compare_digest(key, previous_keys[0]):
        raise ApprovalQueueConfigurationError(
            "Active and previous approval commitment keys must differ."
        )
    return key, previous_keys


def _parse_commitment_rotation_deadline(value: str | None) -> datetime | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalQueueConfigurationError(
            "Previous approval commitment valid-until timestamp must be ISO 8601."
        ) from exc
    if parsed.tzinfo is None:
        raise ApprovalQueueConfigurationError(
            "Previous approval commitment valid-until timestamp must include a timezone."
        )
    return parsed.astimezone(timezone.utc)


def _load_commitment_key(
    secret_manager: SecretManager,
    secret_name: str,
    *,
    role: str,
) -> bytes:
    try:
        secret_value = secret_manager.get_secret(secret_name).reveal()
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
        raise ApprovalQueueConfigurationError(
            f"Approval commitment {role} key could not be resolved from SecretManager."
        ) from None
    key = secret_value.encode("utf-8")
    if len(key) < MIN_COMMITMENT_KEY_BYTES:
        raise ApprovalQueueConfigurationError(
            f"Approval commitment {role} key from SecretManager must contain at least 32 bytes."
        )
    return key
