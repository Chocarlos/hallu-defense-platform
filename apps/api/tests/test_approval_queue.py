from __future__ import annotations

import json
from pathlib import Path

import pytest

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    ApprovalDecision,
    ApprovalDecisionRequest,
    ApprovalListRequest,
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
    create_approval_queue,
)


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
