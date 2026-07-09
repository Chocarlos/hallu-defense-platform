from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hallu_defense.config import Settings
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
    ApprovalAlreadyDecidedError,
    ApprovalDecisionIdentityError,
    ApprovalExecutionGrantConsumedError,
    ApprovalExecutionGrantError,
    ApprovalExecutionGrantExpiredError,
    ApprovalNotFoundError,
    ApprovalQueue,
    ApprovalQueueConfigurationError,
    ApprovalQueueStorageError,
    PostgresApprovalQueueStorage,
    create_approval_queue,
)
from hallu_defense.services.postgres import RecordingSqlProvider


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
    with pytest.raises(ApprovalQueueConfigurationError, match="persistent"):
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


def test_create_approval_queue_accepts_jsonl_backend_in_production(tmp_path: Path) -> None:
    queue = create_approval_queue(
        Settings(
            environment="production",
            policy_version="test",
            auth_required=True,
            allowed_workspace=tmp_path,
            max_command_seconds=5,
            max_output_chars=1000,
            approval_queue_backend="jsonl",
            approval_queue_path=tmp_path / "approval-queue.jsonl",
        )
    )

    approval = queue.request_approval(
        tenant_id="tenant-a",
        trace_id="tr_prod_jsonl",
        tool_call=_tool_call(),
        reason="High-risk action.",
    )

    assert queue.list_for_tenant("tenant-a", ApprovalListRequest())[0].approval_id == approval.approval_id


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


# --- PostgreSQL backend -------------------------------------------------------

_DECIDE_ONCE_SQL = (
    "UPDATE approval_records SET status=%s, decided_at=%s, payload=%s::jsonb "
    "WHERE approval_id=%s AND tenant_id=%s AND status='pending' RETURNING approval_id"
)
_CONSUME_GRANT_ONCE_SQL = (
    "UPDATE approval_execution_grants SET consumed_at=now() "
    "WHERE token_hash=%s AND tenant_id=%s AND tool_call_fingerprint=%s "
    "AND consumed_at IS NULL AND expires_at > now() RETURNING approval_id"
)
_SELECT_GRANT_SQL = (
    "SELECT consumed_at, expires_at FROM approval_execution_grants "
    "WHERE token_hash=%s AND tenant_id=%s"
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


def test_postgres_storage_decide_once_uses_guarded_sql_and_succeeds() -> None:
    provider = RecordingSqlProvider(returning_rows=[{"approval_id": "apr_pg"}])
    storage = PostgresApprovalQueueStorage(connection=provider)
    decided_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    decided = _record(
        status=ApprovalStatus.APPROVED,
        decided_by="reviewer",
        decided_at=decided_at,
    )

    storage.decide_once(decided=decided)

    expected_payload = json.dumps(
        decided.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    assert provider.calls == [
        (
            "execute_returning",
            _DECIDE_ONCE_SQL,
            ("approved", decided_at, expected_payload, "apr_pg", "tenant-a"),
        )
    ]


def test_postgres_storage_decide_once_raises_when_no_row_updated() -> None:
    # 0 rows from the pending-guarded UPDATE means a concurrent decision won.
    provider = RecordingSqlProvider(returning_rows=())
    storage = PostgresApprovalQueueStorage(connection=provider)
    decided = _record(
        status=ApprovalStatus.APPROVED,
        decided_by="reviewer",
        decided_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(ApprovalAlreadyDecidedError):
        storage.decide_once(decided=decided)


def test_postgres_storage_consume_grant_once_uses_guarded_sql_and_returns_id() -> None:
    provider = RecordingSqlProvider(returning_rows=[{"approval_id": "apr_pg"}])
    storage = PostgresApprovalQueueStorage(connection=provider)

    approval_id = storage.consume_grant_once(
        tenant_id="tenant-a",
        token_hash="hash-abc",
        tool_call_fingerprint="fp-xyz",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert approval_id == "apr_pg"
    assert provider.calls == [
        (
            "execute_returning",
            _CONSUME_GRANT_ONCE_SQL,
            ("hash-abc", "tenant-a", "fp-xyz"),
        )
    ]


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
            token_hash="h",
            tool_call_fingerprint="f",
            now=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )

    assert provider.calls[-1] == ("fetch_all", _SELECT_GRANT_SQL, ("h", "tenant-a"))


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
            token_hash="h",
            tool_call_fingerprint="f",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_create_approval_queue_postgres_requires_sql_provider(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="SqlConnectionProvider"):
        create_approval_queue(_postgres_settings(tmp_path))


def test_approval_queue_rejects_storage_path_and_storage_together(tmp_path: Path) -> None:
    with pytest.raises(ApprovalQueueConfigurationError, match="either"):
        ApprovalQueue(
            storage_path=tmp_path / "approval-queue.jsonl",
            storage=PostgresApprovalQueueStorage(connection=RecordingSqlProvider()),
        )


def test_postgres_queue_request_approval_redacts_and_uses_insert_sql(tmp_path: Path) -> None:
    provider = RecordingSqlProvider()
    queue = create_approval_queue(_postgres_settings(tmp_path), sql_provider=provider)

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
    provider = RecordingSqlProvider(
        fetch_all_rows=[{"payload": pending.model_dump(mode="json")}],
        returning_rows=[{"approval_id": pending.approval_id}],
    )
    queue = create_approval_queue(_postgres_settings(tmp_path), sql_provider=provider)

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
    # get_record (SELECT), decide_once (guarded UPDATE ... RETURNING), insert_grant (INSERT).
    assert [call[0] for call in provider.calls] == ["fetch_all", "execute_returning", "execute"]
    assert provider.calls[1][1] == _DECIDE_ONCE_SQL
    # The opaque execution grant value is never persisted raw; only its hash is stored.
    issued = result.execution_grant.execution_token
    for _method, _statement, parameters in provider.calls:
        assert all(issued not in str(parameter) for parameter in parameters)


def test_postgres_queue_consume_execution_grant_succeeds_end_to_end(tmp_path: Path) -> None:
    approved = _record(status=ApprovalStatus.APPROVED, decided_by="reviewer")
    provider = RecordingSqlProvider(
        fetch_all_rows=[{"payload": approved.model_dump(mode="json")}],
        returning_rows=[{"approval_id": approved.approval_id}],
    )
    queue = create_approval_queue(_postgres_settings(tmp_path), sql_provider=provider)

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
    queue = create_approval_queue(_postgres_settings(tmp_path), sql_provider=provider)

    with pytest.raises(ApprovalNotFoundError):
        queue.decide_with_grant(
            "tenant-a",
            ApprovalDecisionRequest(
                approval_id="apr_missing",
                decision=ApprovalDecision.APPROVE,
                decided_by="reviewer",
            ),
        )
