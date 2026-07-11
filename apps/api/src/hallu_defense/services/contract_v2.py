from __future__ import annotations

from types import MappingProxyType

from hallu_defense.domain.models import (
    ClaimVerdict,
    ClaimVerdictV2,
    V2_SCHEMA_VERSION,
    VerdictAction,
    VerdictActionV2,
    VerdictStatus,
    VerdictStatusV2,
    VerificationRun,
    VerificationRunRequest,
    VerificationRunRequestV2,
    VerificationRunV2,
)

LEGACY_STATUS_TO_V2 = MappingProxyType(
    {
        VerdictStatus.SUPPORTED: VerdictStatusV2.SUPPORTED,
        VerdictStatus.PARTIALLY_SUPPORTED: VerdictStatusV2.INSUFFICIENT_EVIDENCE,
        VerdictStatus.CONTRADICTED: VerdictStatusV2.CONTRADICTED,
        VerdictStatus.NOT_FOUND: VerdictStatusV2.UNSUPPORTED,
        VerdictStatus.AMBIGUOUS: VerdictStatusV2.INSUFFICIENT_EVIDENCE,
        VerdictStatus.STALE_SOURCE: VerdictStatusV2.INSUFFICIENT_EVIDENCE,
        VerdictStatus.UNVERIFIABLE: VerdictStatusV2.NOT_VERIFIABLE,
        VerdictStatus.OUT_OF_SCOPE: VerdictStatusV2.NOT_VERIFIABLE,
    }
)

LEGACY_ACTION_TO_V2 = MappingProxyType(
    {
        VerdictAction.ALLOW: VerdictActionV2.ALLOW,
        VerdictAction.ALLOW_WITH_CITATION: VerdictActionV2.ALLOW,
        VerdictAction.REWRITE: VerdictActionV2.REPAIR,
        VerdictAction.ABSTAIN: VerdictActionV2.ABSTAIN,
        VerdictAction.ASK_CLARIFICATION: VerdictActionV2.ASK_CLARIFICATION,
        VerdictAction.BLOCK: VerdictActionV2.BLOCK,
        VerdictAction.REQUIRE_HUMAN_REVIEW: VerdictActionV2.REQUIRE_APPROVAL,
    }
)


def convert_claim_verdict_v2(verdict: ClaimVerdict) -> ClaimVerdictV2:
    """Convert a legacy verdict without inferring policy decisions from action alone."""

    action = LEGACY_ACTION_TO_V2[verdict.action]
    if verdict.action is VerdictAction.REQUIRE_HUMAN_REVIEW:
        status = VerdictStatusV2.REQUIRES_HUMAN_REVIEW
    elif verdict.action is VerdictAction.BLOCK and _has_structured_policy_evidence(verdict):
        status = VerdictStatusV2.BLOCKED_BY_POLICY
    else:
        status = LEGACY_STATUS_TO_V2[verdict.status]
    return ClaimVerdictV2(
        schema_version=V2_SCHEMA_VERSION,
        claim_id=verdict.claim_id,
        status=status,
        confidence=verdict.confidence,
        evidence_ids=list(verdict.evidence_ids),
        action=action,
        reason=verdict.reason,
        validator_trace=dict(verdict.validator_trace),
    )


def convert_verification_run_v2(run: VerificationRun) -> VerificationRunV2:
    return VerificationRunV2(
        schema_version=V2_SCHEMA_VERSION,
        trace_id=run.trace_id,
        tenant_id=run.tenant_id,
        input=dict(run.input),
        claims=list(run.claims),
        evidence=list(run.evidence),
        verdicts=[convert_claim_verdict_v2(verdict) for verdict in run.verdicts],
        final_decision=run.final_decision,
        final_text=run.final_text,
        policy_version=run.policy_version,
        created_at=run.created_at,
    )


def convert_verification_request_v1(request: VerificationRunRequestV2) -> VerificationRunRequest:
    return VerificationRunRequest(
        tenant_id=request.tenant_id,
        message_text=request.message_text,
        documents=list(request.documents),
        tool_outputs=list(request.tool_outputs),
        execution_artifacts=dict(request.execution_artifacts),
        task_type=request.task_type,
        message_id=request.message_id,
    )


def _has_structured_policy_evidence(verdict: ClaimVerdict) -> bool:
    policy_version = verdict.validator_trace.get("policy_version")
    matched_rules = verdict.validator_trace.get("matched_rules")
    return (
        isinstance(policy_version, str)
        and bool(policy_version.strip())
        and isinstance(matched_rules, list)
        and bool(matched_rules)
        and all(isinstance(rule, str) and bool(rule.strip()) for rule in matched_rules)
    )
