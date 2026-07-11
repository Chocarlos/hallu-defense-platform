from __future__ import annotations

import json
import threading
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Self

import pytest

from hallu_defense.config import EnvironmentConfigurationError, Settings
from hallu_defense.domain.models import (
    ApprovalDecision,
    ApprovalDecisionRequest,
    ApprovalListRequest,
    ApprovalRecord,
    ApprovalStatus,
    RiskLevel,
    ToolCallEnvelope,
)
from hallu_defense.services.approvals import (
    REDACTED,
    TOOL_CALL_COMMITMENT_STORAGE_KEY,
    ApprovalAlreadyDecidedError,
    ApprovalDecisionIdentityError,
    ApprovalExecutionGrantConsumedError,
    ApprovalExecutionGrantError,
    ApprovalExecutionGrantExpiredError,
    ApprovalNotFoundError,
    ApprovalQueue,
    ApprovalQueueConfigurationError,
    ApprovalExecutionGrantState,
    ApprovalQueueStorageError,
    PostgresApprovalQueueStorage,
    create_approval_queue,
)
from hallu_defense.services.postgres import (
    PooledPostgresProvider,
    PostgresProviderError,
    RecordingSqlProvider,
)
from hallu_defense.services.secrets import SecretNotFoundError, SecretValue


class StaticCommitmentSecretManager:
    def __init__(
        self,
        value: str = "approval-commitment-key-material-32-bytes-minimum",
        *,
        missing: bool = False,
    ) -> None:
        self.value = value
        self.missing = missing
        self.names: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert field == "value"
        self.names.append(name)
        if self.missing:
            raise SecretNotFoundError("missing test secret")
        return SecretValue(name=name, _value=self.value)


def test_jsonl_approval_queue_persists_and_reloads_pending_records_by_tenant(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approvals" / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)

    tenant_a = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_approval_a",
        tool_call=_tool_call(),
        reason="High-risk repository deletion requires approval.",
        requested_by="agent-a",
    )
    queue.request_approval(
        tenant_id="tenant-b",
        trace_id="tr_approval_b",
        tool_call=_tool_call(),
        reason="Other tenant approval.",
        requested_by="agent-b",
    )

    reloaded = ApprovalQueue(storage_path=queue_path)
    approvals = reloaded.list_for_tenant(
        "tenant-a",
        ApprovalListRequest(status=ApprovalStatus.PENDING),
    )

    assert [approval.approval_id for approval in approvals] == [tenant_a.approval_id]
    assert approvals[0].tenant_id == "tenant-a"
    assert approvals[0].trace_id == "tr_approval_a"
    assert approvals[0].requested_by == "agent-a"


def test_jsonl_approval_queue_persists_decision_snapshot(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_decision",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )

    decided = queue.decide(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
            reason="Approved for maintenance window.",
        ),
    )
    reloaded = ApprovalQueue(storage_path=queue_path)
    approvals = reloaded.list_for_tenant(
        "tenant-a",
        ApprovalListRequest(status=ApprovalStatus.APPROVED),
    )

    assert decided.status == ApprovalStatus.APPROVED
    assert len(queue_path.read_text(encoding="utf-8").splitlines()) == 3
    assert [item.approval_id for item in approvals] == [approval.approval_id]
    assert approvals[0].decided_by == "reviewer"
    assert approvals[0].decision_reason == "Approved for maintenance window."
    assert approvals[0].decided_at is not None


def test_execution_grant_authorizes_matching_tool_call_once_after_reload(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_execution_grant",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )

    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
            reason="Approved.",
        ),
    )

    assert result.execution_grant is not None
    assert result.execution_grant.approval_id == approval.approval_id
    assert result.execution_grant.tenant_id == "tenant-a"
    assert result.execution_grant.tool_name == "delete_repository"
    assert result.execution_grant.execution_token not in queue_path.read_text(encoding="utf-8")

    reloaded = ApprovalQueue(storage_path=queue_path)
    approved = reloaded.consume_execution_grant(
        "tenant-a",
        _tool_call_with_grant(
            approval_id=approval.approval_id,
            execution_token=result.execution_grant.execution_token,
        ),
    )

    assert approved.approval_id == approval.approval_id
    with pytest.raises(ApprovalExecutionGrantConsumedError):
        reloaded.consume_execution_grant(
            "tenant-a",
            _tool_call_with_grant(
                approval_id=approval.approval_id,
                execution_token=result.execution_grant.execution_token,
            ),
        )

    reloaded_after_consumption = ApprovalQueue(storage_path=queue_path)
    with pytest.raises(ApprovalExecutionGrantConsumedError):
        reloaded_after_consumption.consume_execution_grant(
            "tenant-a",
            _tool_call_with_grant(
                approval_id=approval.approval_id,
                execution_token=result.execution_grant.execution_token,
            ),
        )


def test_execution_grant_rejects_mismatched_tool_call(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_execution_grant_mismatch",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )
    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
        ),
    )
    assert result.execution_grant is not None

    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        queue.consume_execution_grant(
            "tenant-a",
            _tool_call_with_grant(
                approval_id=approval.approval_id,
                execution_token=result.execution_grant.execution_token,
                repo="other",
            ),
        )


@pytest.mark.parametrize("substituted_key", ["api_key", "secret", "token", "password"])
def test_execution_grant_rejects_redacted_secret_substitution(
    tmp_path: Path,
    substituted_key: str,
) -> None:
    queue_path = tmp_path / f"approval-{substituted_key}.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    original_values = {
        "api_key": "approved-api-key",
        "secret": "approved-secret",
        "token": "approved-token",
        "password": "approved-password",
    }
    original_call = _sensitive_tool_call(**original_values)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id=f"tr_secret_substitution_{substituted_key}",
        tool_call=original_call,
        reason="High-risk action with secret-bearing input.",
    )
    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
        ),
    )
    assert result.execution_grant is not None
    substituted_values = dict(original_values)
    substituted_values[substituted_key] = f"attacker-{substituted_key}"

    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        queue.consume_execution_grant(
            "tenant-a",
            _sensitive_tool_call(
                **substituted_values,
                approval_id=approval.approval_id,
                execution_token=result.execution_grant.execution_token,
            ),
        )

    # A mismatch does not consume the grant; the exact original still succeeds.
    consumed = queue.consume_execution_grant(
        "tenant-a",
        _sensitive_tool_call(
            **original_values,
            approval_id=approval.approval_id,
            execution_token=result.execution_grant.execution_token,
        ),
    )
    assert consumed.approval_id == approval.approval_id
    persisted = queue_path.read_text(encoding="utf-8")
    assert all(value not in persisted for value in original_values.values())
    assert f"attacker-{substituted_key}" not in persisted
    assert "sha256:" in persisted


def test_tool_call_commitment_supports_stable_hmac_key_without_public_exposure(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "approval-hmac.jsonl"
    commitment_key = b"k" * 32
    queue = ApprovalQueue(storage_path=queue_path, commitment_key=commitment_key)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_hmac_commitment",
        tool_call=_sensitive_tool_call(),
        reason="High-risk action.",
    )

    public_payload = approval.model_dump(mode="json")
    persisted = queue_path.read_text(encoding="utf-8")
    assert TOOL_CALL_COMMITMENT_STORAGE_KEY not in public_payload
    assert "hmac-sha256:" in persisted
    assert "approved-api-key" not in persisted

    reloaded = ApprovalQueue(storage_path=queue_path, commitment_key=commitment_key)
    result = reloaded.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
        ),
    )
    assert result.execution_grant is not None
    consumed = reloaded.consume_execution_grant(
        "tenant-a",
        _sensitive_tool_call(
            approval_id=approval.approval_id,
            execution_token=result.execution_grant.execution_token,
        ),
    )
    assert consumed.approval_id == approval.approval_id


def test_hmac_queue_rejects_legacy_sha256_pending_record_before_grant(
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "legacy-sha-pending.jsonl"
    legacy = ApprovalQueue(storage_path=queue_path)
    approval = legacy.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_legacy_sha_pending",
        tool_call=_tool_call(),
        reason="Legacy pending approval.",
    )
    assert "sha256:" in queue_path.read_text(encoding="utf-8")

    keyed = ApprovalQueue(storage_path=queue_path, commitment_key=b"k" * 32)
    with pytest.raises(ApprovalQueueStorageError, match="legacy unkeyed"):
        keyed.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer",
            ),
        )

    reloaded = ApprovalQueue(storage_path=queue_path)
    pending = reloaded.list_for_tenant("tenant-a", ApprovalListRequest())[0]
    assert pending.status == ApprovalStatus.PENDING


def test_tool_call_commitment_rejects_short_hmac_key() -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="at least 32 bytes"):
        ApprovalQueue(commitment_key=b"too-short")


def test_execution_grant_expires(tmp_path: Path) -> None:
    queue = ApprovalQueue(
        storage_path=tmp_path / "approval-queue.jsonl",
        execution_grant_ttl_seconds=0,
    )
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_execution_grant_expired",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )
    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
        ),
    )
    assert result.execution_grant is not None

    with pytest.raises(ApprovalExecutionGrantExpiredError):
        queue.consume_execution_grant(
            "tenant-a",
            _tool_call_with_grant(
                approval_id=approval.approval_id,
                execution_token=result.execution_grant.execution_token,
            ),
        )


def test_jsonl_approval_queue_preserves_tenant_isolation_after_reload(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_tenant_isolation",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )

    reloaded = ApprovalQueue(storage_path=queue_path)

    with pytest.raises(ApprovalNotFoundError):
        reloaded.decide(
            "tenant-b",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer",
            ),
        )


def test_approval_queue_requires_reviewer_identity_for_decisions(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_missing_reviewer_identity",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )

    with pytest.raises(ApprovalDecisionIdentityError):
        queue.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
            ),
        )


def test_jsonl_approval_queue_preserves_decided_state_after_reload(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)
    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_repeated_decision",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )
    queue.decide(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=approval.approval_id,
            decision=ApprovalDecision.REJECT,
            decided_by="reviewer",
            reason="Not approved.",
        ),
    )

    reloaded = ApprovalQueue(storage_path=queue_path)

    with pytest.raises(ApprovalAlreadyDecidedError):
        reloaded.decide(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=approval.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="second-reviewer",
            ),
        )


def test_jsonl_approval_queue_redacts_sensitive_tool_payloads(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue = ApprovalQueue(storage_path=queue_path)

    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_redaction",
        tool_call=ToolCallEnvelope(
            tool_name="delete_repository",
            input={"repo": "core", "api_key": "short", "nested": {"password": "short"}},
            tool_schema={"type": "object", "properties": {"token": {"const": "short"}}},
            risk_level=RiskLevel.HIGH,
            approval_required=True,
            caller_context={"subject": "agent", "token": "short"},
        ),
        reason="High-risk action.",
    )

    raw_text = queue_path.read_text(encoding="utf-8")

    assert "short" not in raw_text
    assert approval.tool_call.input["api_key"] == REDACTED
    assert approval.tool_call.input["nested"] == {"password": REDACTED}
    assert approval.tool_call.tool_schema["properties"] == {"token": REDACTED}
    assert approval.tool_call.caller_context["token"] == REDACTED
    assert REDACTED in raw_text


def test_create_approval_queue_rejects_memory_backend_in_production(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="PostgreSQL"):
        create_approval_queue(
            Settings(
                environment="production",
                policy_version="test",
                auth_required=True,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1000,
                approval_queue_backend="memory",
            )
        )


@pytest.mark.parametrize(
    "environment",
    ["production", "staging", " production ", " STAGING "],
)
def test_production_like_queue_rejects_process_local_jsonl_backend(
    tmp_path: Path,
    environment: str,
) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="PostgreSQL"):
        create_approval_queue(
            Settings(
                environment=environment,
                policy_version="test",
                auth_required=True,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1000,
                approval_queue_backend="jsonl",
                approval_queue_path=tmp_path / "approval-queue.jsonl",
                approval_tool_call_commitment_secret_name=(
                    "approvals/tool-call-commitment-key"
                ),
                secrets_backend="vault",
            ),
            secret_manager=StaticCommitmentSecretManager(),
        )


def test_approval_queue_factory_rejects_unknown_environment(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentConfigurationError, match="HALLU_DEFENSE_ENV"):
        create_approval_queue(
            Settings(
                environment="prod",
                policy_version="test",
                auth_required=False,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1000,
                approval_queue_backend="memory",
            )
        )


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_production_like_queue_rejects_unkeyed_sha256_fallback(
    tmp_path: Path,
    environment: str,
) -> None:
    settings = Settings(
        environment=environment,
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        approval_queue_backend="postgres",
        secrets_backend="vault",
    )

    with pytest.raises(ApprovalQueueConfigurationError, match="SecretManager name"):
        create_approval_queue(
            settings,
            sql_provider=RecordingSqlProvider(),
            secret_manager=StaticCommitmentSecretManager(),
        )


def test_production_queue_rejects_raw_explicit_commitment_key(tmp_path: Path) -> None:
    settings = _postgres_settings(tmp_path)

    with pytest.raises(ApprovalQueueConfigurationError, match="logical SecretManager"):
        create_approval_queue(
            settings,
            sql_provider=RecordingSqlProvider(),
            commitment_key=b"x" * 32,
        )


def test_production_queue_rejects_missing_or_short_secret_manager_key(
    tmp_path: Path,
) -> None:
    settings = _postgres_settings(tmp_path)
    provider = RecordingSqlProvider()

    with pytest.raises(ApprovalQueueConfigurationError, match="requires SecretManager"):
        create_approval_queue(settings, sql_provider=provider)
    with pytest.raises(ApprovalQueueConfigurationError, match="at least 32 bytes"):
        create_approval_queue(
            settings,
            sql_provider=provider,
            secret_manager=StaticCommitmentSecretManager("short"),
        )
    with pytest.raises(ApprovalQueueConfigurationError, match="could not be resolved"):
        create_approval_queue(
            settings,
            sql_provider=provider,
            secret_manager=StaticCommitmentSecretManager(missing=True),
        )


def test_create_approval_queue_rejects_non_positive_execution_grant_ttl(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="TTL"):
        create_approval_queue(
            Settings(
                environment="local",
                policy_version="test",
                auth_required=False,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1000,
                approval_execution_grant_ttl_seconds=0,
            )
        )


def test_jsonl_approval_queue_fails_closed_on_corrupt_record(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue_path.write_text(
        json.dumps({"record_type": "unknown", "payload": {}}),
        encoding="utf-8",
    )

    with pytest.raises(ApprovalQueueStorageError, match="unsupported record_type"):
        ApprovalQueue(storage_path=queue_path)


def test_jsonl_approval_queue_fails_closed_on_invalid_payload(tmp_path: Path) -> None:
    queue_path = tmp_path / "approval-queue.jsonl"
    queue_path.write_text(
        json.dumps({"record_type": "approval_record", "payload": {}}),
        encoding="utf-8",
    )

    with pytest.raises(ApprovalQueueStorageError, match="payload is invalid"):
        ApprovalQueue(storage_path=queue_path)


def _tool_call() -> ToolCallEnvelope:
    return ToolCallEnvelope(
        tool_name="delete_repository",
        input={"repo": "core"},
        tool_schema={"type": "object"},
        risk_level=RiskLevel.HIGH,
        approval_required=True,
        caller_context={"subject": "agent"},
    )


def _tool_call_with_grant(
    *,
    approval_id: str,
    execution_token: str,
    repo: str = "core",
) -> ToolCallEnvelope:
    return ToolCallEnvelope(
        tool_name="delete_repository",
        input={"repo": repo},
        tool_schema={"type": "object"},
        risk_level=RiskLevel.HIGH,
        approval_required=True,
        caller_context={"subject": "agent"},
        approval_id=approval_id,
        approval_execution_token=execution_token,
    )


def _sensitive_tool_call(
    *,
    api_key: str = "approved-api-key",
    secret: str = "approved-secret",
    token: str = "approved-token",
    password: str = "approved-password",
    approval_id: str | None = None,
    execution_token: str | None = None,
) -> ToolCallEnvelope:
    return ToolCallEnvelope(
        tool_name="deploy_release",
        input={
            "release": "2026.07",
            "api_key": api_key,
            "nested": {
                "secret": secret,
                "token": token,
                "password": password,
            },
        },
        tool_schema={"type": "object"},
        risk_level=RiskLevel.HIGH,
        approval_required=True,
        caller_context={"subject": "agent"},
        approval_id=approval_id,
        approval_execution_token=execution_token,
    )


# --- PostgreSQL backend -------------------------------------------------------

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
_INSERT_RECORD_SQL = (
    "INSERT INTO approval_records "
    "(approval_id, tenant_id, trace_id, status, payload, created_at) "
    "VALUES (%s, %s, %s, %s, %s::jsonb, %s)"
)


def _postgres_settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="production",
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        approval_queue_backend="postgres",
        approval_tool_call_commitment_secret_name=("approvals/tool-call-commitment-key"),
        secrets_backend="vault",
    )


def _record(
    *,
    approval_id: str = "apr_pg",
    tenant_id: str = "tenant-a",
    status: ApprovalStatus = ApprovalStatus.PENDING,
    decided_by: str | None = None,
    decided_at: datetime | None = None,
) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=approval_id,
        tenant_id=tenant_id,
        trace_id="tr_pg",
        tool_call=_tool_call(),
        status=status,
        risk_level=RiskLevel.HIGH,
        reason="High-risk action.",
        decided_by=decided_by,
        decided_at=decided_at,
    )


def _grant_state(*, token_hash: str = "a" * 64) -> ApprovalExecutionGrantState:
    return ApprovalExecutionGrantState(
        approval_id="apr_pg",
        tenant_id="tenant-a",
        tool_call_fingerprint="sha256:" + "b" * 64,
        token_hash=token_hash,
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )


class AtomicApprovalCursor:
    def __init__(self, connection: AtomicApprovalConnection) -> None:
        self._connection = connection
        self._rows: list[Mapping[str, object]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        self._connection.executions.append((statement, tuple(parameters)))
        self._rows = []
        if statement == _DECIDE_ONCE_SQL:
            if self._connection.working_status == "pending":
                self._connection.working_status = str(parameters[0])
                self._rows = [{"approval_id": "apr_pg"}]
            return
        if statement == _INSERT_GRANT_SQL:
            if self._connection.pool.fail_grant_insert:
                raise RuntimeError("injected grant insert failure")
            self._connection.working_grants += 1

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        return list(self._rows)


class AtomicApprovalConnection:
    def __init__(self, pool: AtomicApprovalPool) -> None:
        self.pool = pool
        self.working_status = pool.status
        self.working_grants = pool.grants
        self.executions: list[tuple[str, tuple[object, ...]]] = []

    def cursor(self) -> AtomicApprovalCursor:
        return AtomicApprovalCursor(self)


class AtomicApprovalConnectionContext:
    def __init__(self, pool: AtomicApprovalPool) -> None:
        self._pool = pool
        self.connection: AtomicApprovalConnection | None = None
        self.committed = False
        self.rolled_back = False

    def __enter__(self) -> AtomicApprovalConnection:
        self._pool.state_lock.acquire()
        self.connection = AtomicApprovalConnection(self._pool)
        return self.connection

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if exc_type is None:
                assert self.connection is not None
                self._pool.status = self.connection.working_status
                self._pool.grants = self.connection.working_grants
                self.committed = True
            else:
                self.rolled_back = True
        finally:
            self._pool.state_lock.release()


class AtomicApprovalPool:
    def __init__(self, *, fail_grant_insert: bool = False) -> None:
        self.status = "pending"
        self.grants = 0
        self.fail_grant_insert = fail_grant_insert
        self.state_lock = threading.Lock()
        self.contexts: list[AtomicApprovalConnectionContext] = []

    def connection(self) -> AbstractContextManager[AtomicApprovalConnection]:
        context = AtomicApprovalConnectionContext(self)
        self.contexts.append(context)
        return context

    def close(self) -> None:
        return None


def test_pooled_postgres_grant_failure_rolls_decision_back_to_pending() -> None:
    pool = AtomicApprovalPool(fail_grant_insert=True)
    provider = PooledPostgresProvider(
        dsn="postgresql://localhost/approval-test",
        pool=pool,
    )
    storage = PostgresApprovalQueueStorage(connection=provider)
    decided = _record(
        status=ApprovalStatus.APPROVED,
        decided_by="reviewer",
        decided_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(PostgresProviderError, match="transaction execute failed"):
        storage.decide_with_grant_once(
            decided=decided,
            grant_state=_grant_state(),
        )

    assert pool.status == "pending"
    assert pool.grants == 0
    assert len(pool.contexts) == 1
    assert pool.contexts[0].committed is False
    assert pool.contexts[0].rolled_back is True


def test_pooled_postgres_concurrent_decision_creates_exactly_one_grant() -> None:
    pool = AtomicApprovalPool()
    provider = PooledPostgresProvider(
        dsn="postgresql://localhost/approval-test",
        pool=pool,
    )
    storage = PostgresApprovalQueueStorage(connection=provider)
    decided = _record(
        status=ApprovalStatus.APPROVED,
        decided_by="reviewer",
        decided_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    start = threading.Barrier(3)
    outcomes: list[str] = []
    outcome_lock = threading.Lock()

    def decide(token_hash: str) -> None:
        start.wait()
        try:
            storage.decide_with_grant_once(
                decided=decided,
                grant_state=_grant_state(token_hash=token_hash),
            )
        except ApprovalAlreadyDecidedError:
            outcome = "conflict"
        else:
            outcome = "approved"
        with outcome_lock:
            outcomes.append(outcome)

    workers = [threading.Thread(target=decide, args=(character * 64,)) for character in ("c", "d")]
    for worker in workers:
        worker.start()
    start.wait()
    for worker in workers:
        worker.join(timeout=5)

    assert all(not worker.is_alive() for worker in workers)
    assert sorted(outcomes) == ["approved", "conflict"]
    assert pool.status == "approved"
    assert pool.grants == 1
    assert sum(context.committed for context in pool.contexts) == 1
    assert sum(context.rolled_back for context in pool.contexts) == 1


def test_postgres_storage_decision_and_grant_use_one_transaction() -> None:
    provider = RecordingSqlProvider(returning_rows=[{"approval_id": "apr_pg"}])
    decided_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    storage = PostgresApprovalQueueStorage(
        connection=provider,
        clock=lambda: decided_at,
    )
    decided = _record(
        status=ApprovalStatus.APPROVED,
        decided_by="reviewer",
        decided_at=decided_at,
    )

    grant_state = _grant_state()

    storage.decide_with_grant_once(
        decided=decided,
        grant_state=grant_state,
    )

    expected_payload = json.dumps(
        decided.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    assert provider.calls == [
        (
            "execute_returning",
            _DECIDE_ONCE_SQL,
            ("approved", decided_at, expected_payload, "apr_pg", "tenant-a"),
        ),
        (
            "execute",
            _INSERT_GRANT_SQL,
            (
                grant_state.token_hash,
                grant_state.approval_id,
                grant_state.tenant_id,
                grant_state.tool_call_fingerprint,
                grant_state.expires_at,
                None,
                datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ),
    ]


def test_postgres_storage_atomic_decision_raises_before_grant_when_no_row_updated() -> None:
    # 0 rows from the pending-guarded UPDATE means a concurrent decision won.
    provider = RecordingSqlProvider(returning_rows=())
    storage = PostgresApprovalQueueStorage(connection=provider)
    decided = _record(
        status=ApprovalStatus.APPROVED,
        decided_by="reviewer",
        decided_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(ApprovalAlreadyDecidedError):
        storage.decide_with_grant_once(
            decided=decided,
            grant_state=_grant_state(),
        )

    assert [call[0] for call in provider.calls] == ["execute_returning"]


def test_postgres_storage_consume_grant_once_uses_guarded_sql_and_returns_id() -> None:
    provider = RecordingSqlProvider(returning_rows=[{"approval_id": "apr_pg"}])
    storage = PostgresApprovalQueueStorage(connection=provider)

    approval_id = storage.consume_grant_once(
        tenant_id="tenant-a",
        approval_id="apr_pg",
        token_hash="hash-abc",
        tool_call_fingerprint="fp-xyz",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert approval_id == "apr_pg"
    assert provider.calls == [
        (
            "execute_returning",
            _CONSUME_GRANT_ONCE_SQL,
            ("hash-abc", "apr_pg", "tenant-a", "fp-xyz"),
        )
    ]


def test_postgres_storage_consume_grant_rejects_inconsistent_approval_id() -> None:
    provider = RecordingSqlProvider(returning_rows=[{"approval_id": "apr_other"}])
    storage = PostgresApprovalQueueStorage(connection=provider)

    with pytest.raises(ApprovalQueueStorageError, match="inconsistent approval_id"):
        storage.consume_grant_once(
            tenant_id="tenant-a",
            approval_id="apr_expected",
            token_hash="hash-abc",
            tool_call_fingerprint="fp-xyz",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    assert provider.calls[0][2] == (
        "hash-abc",
        "apr_expected",
        "tenant-a",
        "fp-xyz",
    )


def test_postgres_storage_consume_grant_once_raises_consumed_on_zero_rows() -> None:
    provider = RecordingSqlProvider(
        returning_rows=(),
        fetch_all_rows=[
            {
                "consumed_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "expires_at": datetime(2030, 1, 1, tzinfo=timezone.utc),
            }
        ],
    )
    storage = PostgresApprovalQueueStorage(connection=provider)

    with pytest.raises(ApprovalExecutionGrantConsumedError):
        storage.consume_grant_once(
            tenant_id="tenant-a",
            approval_id="apr_pg",
            token_hash="h",
            tool_call_fingerprint="f",
            now=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )

    assert provider.calls[-1] == (
        "fetch_all",
        _SELECT_GRANT_SQL,
        ("h", "apr_pg", "tenant-a", "f"),
    )


def test_postgres_storage_consume_grant_once_raises_expired_on_zero_rows() -> None:
    provider = RecordingSqlProvider(
        returning_rows=(),
        fetch_all_rows=[
            {
                "consumed_at": None,
                "expires_at": datetime(2020, 1, 1, tzinfo=timezone.utc),
            }
        ],
    )
    storage = PostgresApprovalQueueStorage(connection=provider)

    with pytest.raises(ApprovalExecutionGrantExpiredError):
        storage.consume_grant_once(
            tenant_id="tenant-a",
            approval_id="apr_pg",
            token_hash="h",
            tool_call_fingerprint="f",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_postgres_storage_consume_grant_once_raises_invalid_when_absent() -> None:
    provider = RecordingSqlProvider(returning_rows=(), fetch_all_rows=())
    storage = PostgresApprovalQueueStorage(connection=provider)

    with pytest.raises(ApprovalExecutionGrantError, match="invalid"):
        storage.consume_grant_once(
            tenant_id="tenant-a",
            approval_id="apr_pg",
            token_hash="h",
            tool_call_fingerprint="f",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_postgres_storage_consume_grant_once_raises_mismatch_when_fingerprint_differs() -> None:
    # Grant exists, is unconsumed and unexpired, yet the atomic guard returned
    # 0 rows -> the fingerprint did not match this tool call.
    provider = RecordingSqlProvider(
        returning_rows=(),
        fetch_all_rows=[
            {"consumed_at": None, "expires_at": datetime(2030, 1, 1, tzinfo=timezone.utc)}
        ],
    )
    storage = PostgresApprovalQueueStorage(connection=provider)

    with pytest.raises(ApprovalExecutionGrantError, match="does not match"):
        storage.consume_grant_once(
            tenant_id="tenant-a",
            approval_id="apr_pg",
            token_hash="h",
            tool_call_fingerprint="f",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_create_approval_queue_postgres_requires_sql_provider(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="SqlConnectionProvider"):
        create_approval_queue(
            _postgres_settings(tmp_path),
            secret_manager=StaticCommitmentSecretManager(),
        )


def test_approval_queue_rejects_storage_path_and_storage_together(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="either"):
        ApprovalQueue(
            storage_path=tmp_path / "approval-queue.jsonl",
            storage=PostgresApprovalQueueStorage(connection=RecordingSqlProvider()),
        )


def test_postgres_queue_request_approval_redacts_and_uses_insert_sql(tmp_path: Path) -> None:
    provider = RecordingSqlProvider()
    queue = create_approval_queue(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=StaticCommitmentSecretManager(),
    )

    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_pg",
        tool_call=ToolCallEnvelope(
            tool_name="delete_repository",
            input={"repo": "core", "api_key": "topsecret", "nested": {"password": "topsecret"}},
            tool_schema={"type": "object", "properties": {"token": {"const": "topsecret"}}},
            risk_level=RiskLevel.HIGH,
            approval_required=True,
            caller_context={"subject": "agent", "token": "topsecret"},
        ),
        reason="High-risk action.",
    )

    assert provider.calls[0][0] == "execute"
    assert provider.calls[0][1] == _INSERT_RECORD_SQL
    # Redaction parity with JSONL: secrets never reach the database parameters.
    for _method, _statement, parameters in provider.calls:
        assert all("topsecret" not in str(parameter) for parameter in parameters)
    assert approval.tool_call.input["api_key"] == REDACTED
    assert approval.tool_call.caller_context["token"] == REDACTED


def test_postgres_queue_decide_with_grant_issues_grant_end_to_end(tmp_path: Path) -> None:
    pending = _record()
    pending_payload = pending.model_dump(mode="json")
    pending_payload[TOOL_CALL_COMMITMENT_STORAGE_KEY] = ApprovalQueue(
        commitment_key=b"approval-commitment-key-material-32-bytes-minimum"
    )._tool_call_commitment(pending.tool_call)
    provider = RecordingSqlProvider(
        fetch_all_rows=[{"payload": pending_payload}],
        returning_rows=[{"approval_id": pending.approval_id}],
    )
    queue = create_approval_queue(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=StaticCommitmentSecretManager(),
    )

    result = queue.decide_with_grant(
        "tenant-a",
        ApprovalDecisionRequest(
            approval_id=pending.approval_id,
            decision=ApprovalDecision.APPROVE,
            decided_by="reviewer",
        ),
    )

    assert result.approval.status == ApprovalStatus.APPROVED
    assert result.execution_grant is not None
    # get_record, then one transaction containing guarded decision + grant insert.
    assert [call[0] for call in provider.calls] == ["fetch_all", "execute_returning", "execute"]
    assert provider.calls[1][1] == _DECIDE_ONCE_SQL
    # The opaque execution grant value is never persisted raw; only its hash is stored.
    issued = result.execution_grant.execution_token
    for _method, _statement, parameters in provider.calls:
        assert all(issued not in str(parameter) for parameter in parameters)


def test_postgres_queue_never_falls_back_to_redacted_legacy_fingerprint(
    tmp_path: Path,
) -> None:
    pending = _record()
    provider = RecordingSqlProvider(
        fetch_all_rows=[{"payload": pending.model_dump(mode="json")}],
        returning_rows=[{"approval_id": pending.approval_id}],
    )
    queue = create_approval_queue(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=StaticCommitmentSecretManager(),
    )

    with pytest.raises(ApprovalQueueStorageError, match="original tool-call commitment"):
        queue.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id=pending.approval_id,
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer",
            ),
        )

    assert [call[0] for call in provider.calls] == ["fetch_all"]


def test_postgres_queue_consume_execution_grant_succeeds_end_to_end(tmp_path: Path) -> None:
    approved = _record(status=ApprovalStatus.APPROVED, decided_by="reviewer")
    provider = RecordingSqlProvider(
        fetch_all_rows=[{"payload": approved.model_dump(mode="json")}],
        returning_rows=[{"approval_id": approved.approval_id}],
    )
    queue = create_approval_queue(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=StaticCommitmentSecretManager(),
    )

    record = queue.consume_execution_grant(
        "tenant-a",
        _tool_call_with_grant(
            approval_id=approved.approval_id,
            execution_token="tok_" + "x" * 24,
        ),
    )

    assert record.approval_id == approved.approval_id
    # get_record (SELECT) then the atomic consume-once UPDATE ... RETURNING.
    assert [call[0] for call in provider.calls] == ["fetch_all", "execute_returning"]
    assert provider.calls[1][1] == _CONSUME_GRANT_ONCE_SQL
    # The raw execution token is hashed before it reaches the database.
    for _method, _statement, parameters in provider.calls:
        assert all("tok_" not in str(parameter) for parameter in parameters)


def test_postgres_queue_decide_with_grant_rejects_unknown_approval(tmp_path: Path) -> None:
    provider = RecordingSqlProvider(fetch_all_rows=())
    queue = create_approval_queue(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=StaticCommitmentSecretManager(),
    )

    with pytest.raises(ApprovalNotFoundError):
        queue.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id="apr_missing",
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer",
            ),
        )
