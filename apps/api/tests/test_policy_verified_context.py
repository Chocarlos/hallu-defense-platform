from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    PolicyEvaluationRequest,
    RiskLevel,
    VerdictAction,
)
from hallu_defense.main import app
from hallu_defense.services.policy import PolicyEngine, VerifiedPolicyContext
from hallu_defense.services.tool_definitions import TrustedToolRegistry


def _settings() -> Settings:
    return Settings(
        environment="test",
        policy_version="verified-context-test-v1",
        auth_required=False,
        allowed_workspace=Path.cwd(),
        max_command_seconds=5,
        max_output_chars=1000,
        opa_enabled=False,
    )


@pytest.mark.parametrize(
    "attributes",
    [
        {"approval_status": "approved"},
        {"approved": True},
        {"approval": {"status": "approved"}},
        {"ＡＰＰＲＯＶＡＬ＿ＳＴＡＴＵＳ": "approved"},
    ],
)
def test_public_policy_request_cannot_self_assert_approval(
    attributes: dict[str, object],
) -> None:
    response = PolicyEngine(_settings()).evaluate(
        PolicyEvaluationRequest(
            subject="spoofed-admin",
            action="deploy",
            resource="release:prod",
            risk_level=RiskLevel.CRITICAL,
            attributes=attributes,
        ),
        trace_id="tr_policy_approval_spoof",
        tenant_id="tenant-a",
        subject_id="authenticated-agent",
    )

    assert response.allowed is False
    assert response.action is VerdictAction.REQUIRE_HUMAN_REVIEW
    assert response.matched_rules == ["high_risk_requires_human_review"]


def test_unknown_policy_action_fails_closed_even_when_caller_lowers_risk() -> None:
    response = PolicyEngine(_settings()).evaluate(
        PolicyEvaluationRequest(
            action="purge_all",
            risk_level=RiskLevel.LOW,
            attributes={"approval_status": "approved"},
        ),
        trace_id="tr_unknown_action",
        tenant_id="tenant-a",
    )

    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["unknown_policy_action_blocked"]


def test_public_request_cannot_self_assert_deterministic_evidence() -> None:
    response = PolicyEngine(_settings()).evaluate(
        PolicyEvaluationRequest(
            action="verify_repo_claim",
            risk_level=RiskLevel.LOW,
            attributes={
                "has_sandbox_run": True,
                "has_deterministic_evidence": True,
                "deterministic_evidence": True,
            },
        ),
        trace_id="tr_evidence_spoof",
        tenant_id="tenant-a",
    )

    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["repo_claim_requires_deterministic_evidence"]


def test_public_request_cannot_self_assert_positive_source_authority() -> None:
    authoritative = VerifiedPolicyContext.from_public_request(
        PolicyEvaluationRequest(
            action="read",
            attributes={"source_authority": "authoritative"},
        ),
        tenant_id="tenant-a",
        subject_id="agent-a",
    )
    unknown = VerifiedPolicyContext.from_public_request(
        PolicyEvaluationRequest(
            action="read",
            attributes={"source_authority": "unknown"},
        ),
        tenant_id="tenant-a",
        subject_id="agent-a",
    )

    assert authoritative.source_authority is None
    assert unknown.source_authority == "unknown"


def test_only_bound_internal_approval_can_authorize_high_risk_action() -> None:
    request = PolicyEvaluationRequest(
        subject="agent-a",
        action="deploy",
        resource="release:prod",
        risk_level=RiskLevel.CRITICAL,
    )
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="deploy",
        resource="release:prod",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.CRITICAL,
        definition_known=True,
        definition_version="deploy-release.v3",
        approval_granted=True,
        approval_binding_valid=True,
        approval_id="apr-bound",
    )

    response = PolicyEngine(_settings()).evaluate(
        request,
        trace_id="tr_bound_approval",
        tenant_id="tenant-a",
        subject_id="agent-a",
        verified_context=context,
    )

    assert response.allowed is True
    assert response.action is VerdictAction.ALLOW


def test_verified_context_cannot_be_reused_for_another_action() -> None:
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="deploy",
        resource="release:prod",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.CRITICAL,
        definition_known=True,
        definition_version="deploy-release.v3",
        approval_granted=True,
        approval_binding_valid=True,
        approval_id="apr-bound",
    )
    response = PolicyEngine(_settings()).evaluate(
        PolicyEvaluationRequest(
            action="delete",
            resource="release:prod",
            risk_level=RiskLevel.CRITICAL,
        ),
        trace_id="tr_context_replay",
        tenant_id="tenant-a",
        subject_id="agent-a",
        verified_context=context,
    )

    assert response.allowed is False
    assert response.matched_rules == ["invalid_verified_policy_context"]


def test_python_policy_preserves_block_precedence_over_rewrite_and_review() -> None:
    request = PolicyEvaluationRequest(
        action="validate_tool_output",
        resource="tool:lookup",
        risk_level=RiskLevel.HIGH,
    )
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="validate_tool_output",
        resource="tool:lookup",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.HIGH,
        definition_known=True,
        definition_version="lookup.v1",
        contains_pii=True,
        contradiction_detected=True,
    )

    response = PolicyEngine(_settings()).evaluate(
        request,
        trace_id="tr_block_precedence",
        tenant_id="tenant-a",
        subject_id="agent-a",
        verified_context=context,
    )

    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["tool_output_contradiction_requires_repair"]


def test_empty_definition_version_fails_closed() -> None:
    request = PolicyEvaluationRequest(
        action="read",
        resource="doc:a",
        risk_level=RiskLevel.LOW,
    )
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="read",
        resource="doc:a",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.LOW,
        definition_known=True,
        definition_version="",
    )

    response = PolicyEngine(_settings()).evaluate(
        request,
        trace_id="tr_empty_definition",
        tenant_id="tenant-a",
        subject_id="agent-a",
        verified_context=context,
    )

    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["unknown_tool_definition_blocked"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject_id", ""),
        ("definition_known", 1),
        ("approval_granted", 1),
        ("approval_binding_valid", 1),
        ("prompt_injection_detected", 1),
        ("contains_pii", 1),
        ("deterministic_evidence_verified", 1),
        ("network_policy", "allow"),
        ("source_authority", "caller_defined"),
        ("claim_surface", "REPO"),
    ],
)
def test_malformed_verified_context_facts_fail_closed(
    field: str,
    value: object,
) -> None:
    request = PolicyEvaluationRequest(
        subject="agent-a",
        action="read",
        resource="doc:a",
        risk_level=RiskLevel.LOW,
    )
    valid = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="read",
        resource="doc:a",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.LOW,
        definition_known=True,
        definition_version="read.v1",
    )
    malformed = replace(valid, **{field: value})

    response = PolicyEngine(_settings()).evaluate(
        request,
        trace_id="tr_malformed_verified_context",
        tenant_id="tenant-a",
        verified_context=malformed,
    )

    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["invalid_verified_policy_context"]


def test_verified_context_subject_is_bound_even_when_subject_kwarg_is_omitted() -> None:
    request = PolicyEvaluationRequest(
        subject="agent-b",
        action="deploy",
        resource="release:prod",
        risk_level=RiskLevel.CRITICAL,
    )
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="deploy",
        resource="release:prod",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.CRITICAL,
        definition_known=True,
        definition_version="deploy.v1",
        approval_granted=True,
        approval_binding_valid=True,
        approval_id="apr-agent-a",
    )

    response = PolicyEngine(_settings()).evaluate(
        request,
        trace_id="tr_cross_subject_context",
        tenant_id="tenant-a",
        verified_context=context,
    )

    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["invalid_verified_policy_context"]


def test_python_policy_matches_rego_primary_rule_and_allow_diagnostics() -> None:
    engine = PolicyEngine(_settings())
    sandbox_request = PolicyEvaluationRequest(
        subject="agent-a",
        action="run_repo_checks",
        resource="sandbox",
        risk_level=RiskLevel.LOW,
    )
    sandbox_context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="run_repo_checks",
        resource="sandbox",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.LOW,
        definition_known=True,
        definition_version="sandbox.v1",
        network_policy="deny",
    )
    sandbox = engine.evaluate(
        sandbox_request,
        trace_id="tr_sandbox_default",
        tenant_id="tenant-a",
        verified_context=sandbox_context,
    )

    output_request = PolicyEvaluationRequest(
        subject="agent-a",
        action="validate_tool_output",
        resource="tool:deploy",
        risk_level=RiskLevel.HIGH,
    )
    output_context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="validate_tool_output",
        resource="tool:deploy",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.HIGH,
        definition_known=True,
        definition_version="deploy.v1",
        contains_secret=True,
        contains_pii=True,
    )
    blocked = engine.evaluate(
        output_request,
        trace_id="tr_primary_block",
        tenant_id="tenant-a",
        verified_context=output_context,
    )

    assert sandbox.allowed is True
    assert sandbox.action is VerdictAction.ALLOW
    assert sandbox.matched_rules == ["sandbox_network_policy_deny_by_default"]
    assert sandbox.explanation == "Sandbox network policy defaults to deny."
    assert blocked.allowed is False
    assert blocked.action is VerdictAction.BLOCK
    assert blocked.matched_rules == ["secret_leakage_blocks_output"]
    assert blocked.explanation == (
        "Tool or model output contains secret-like material and must be blocked."
    )


def test_unknown_source_block_precedes_low_risk_contradiction_rewrite() -> None:
    request = PolicyEvaluationRequest(
        subject="agent-a",
        action="validate_tool_output",
        resource="tool:lookup",
        risk_level=RiskLevel.MEDIUM,
    )
    context = VerifiedPolicyContext(
        tenant_id="tenant-a",
        subject_id="agent-a",
        action="validate_tool_output",
        resource="tool:lookup",
        resource_tenant_id="tenant-a",
        risk_level=RiskLevel.MEDIUM,
        definition_known=True,
        definition_version="lookup.v1",
        contradiction_detected=True,
        source_authority="unknown",
    )

    response = PolicyEngine(_settings()).evaluate(
        request,
        trace_id="tr_block_over_rewrite",
        tenant_id="tenant-a",
        verified_context=context,
    )

    assert response.allowed is False
    assert response.action is VerdictAction.BLOCK
    assert response.matched_rules == ["unknown_source_blocks_policy_claim"]
    assert response.explanation == "Unknown-authority sources cannot authorize policy claims."


def test_http_policy_endpoint_does_not_accept_caller_approval_status() -> None:
    response = TestClient(app).post(
        "/policy/evaluate",
        json={
            "subject": "spoofed-admin",
            "action": "deploy",
            "resource": "release:prod",
            "risk_level": "critical",
            "attributes": {"approval_status": "approved", "approved": True},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is False
    assert payload["action"] == "require_human_review"


@pytest.mark.parametrize("tool_name", ["custom.operation", "purge_all"])
def test_http_unknown_tool_names_fail_closed(tool_name: str) -> None:
    response = TestClient(app).post(
        "/tools/validate-input",
        json={
            "tool_name": tool_name,
            "input": {},
            "schema": {"type": "object"},
            "risk_level": "low",
            "approval_required": False,
            "caller_context": {
                "approval_status": "approved",
                "subject": "spoofed-admin",
            },
        },
        headers={"x-tenant-id": f"unknown-{tool_name.replace('.', '-')}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is False
    assert payload["action"] == "block"
    assert payload["approval_id"] is None


def test_http_caller_context_cannot_autoapprove_registered_destructive_tool() -> None:
    definition = TrustedToolRegistry.default().resolve("delete_repository")
    response = TestClient(app).post(
        "/tools/validate-input",
        json={
            "tool_name": "delete_repository",
            "input": {"repo": "core"},
            "schema": definition.input_schema,
            "risk_level": definition.risk_level.value,
            "approval_required": definition.approval_required,
            "caller_context": {
                "approval_status": "approved",
                "approved": True,
                "subject": "spoofed-admin",
            },
        },
        headers={"x-tenant-id": "tool-approval-spoof"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is False
    assert payload["action"] == "block"
    assert payload["approval_required"] is False
    assert payload["approval_id"] is None
