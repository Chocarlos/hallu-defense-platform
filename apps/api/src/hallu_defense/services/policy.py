from __future__ import annotations

import time
from typing import Protocol

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    RiskLevel,
    VerdictAction,
)
from hallu_defense.services.metrics import PrometheusMetrics
from hallu_defense.services.opa import OpaPolicyEvaluationError

SENSITIVE_ACTIONS = {"delete", "deploy", "send_email", "transfer", "charge", "write_file"}
REPO_CLAIM_ACTIONS = {
    "verify_build_claim",
    "verify_repo_claim",
    "verify_test_claim",
}
TOOL_OUTPUT_ACTIONS = {
    "tool_output",
    "validate_output",
    "validate_tool_output",
}


class PolicyEvaluator(Protocol):
    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str,
    ) -> PolicyEvaluationResponse | None: ...


class PolicyEngine:
    def __init__(
        self,
        settings: Settings,
        opa_evaluator: PolicyEvaluator | None = None,
        metrics: PrometheusMetrics | None = None,
    ) -> None:
        self._settings = settings
        self._opa_evaluator = opa_evaluator
        self._metrics = metrics

    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str = "local-dev",
    ) -> PolicyEvaluationResponse:
        started_at = time.perf_counter()
        opa_response = self._evaluate_opa(request, trace_id, tenant_id)
        if opa_response is not None:
            return self._record_response(opa_response, started_at)

        action_name = request.action.strip().lower()

        if self._cross_tenant(request, tenant_id):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["cross_tenant_access_denied"],
                explanation="Request tenant does not match the target resource tenant.",
            ), started_at)

        if self._bool_attr(request, "prompt_injection_detected", "prompt_injection"):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["prompt_injection_blocks_untrusted_instruction"],
                explanation="Prompt injection attempts cannot override system or policy instructions.",
            ), started_at)

        if self._bool_attr(
            request,
            "indirect_prompt_injection_detected",
            "indirect_prompt_injection",
        ):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["indirect_prompt_injection_blocks_document_instruction"],
                explanation="Retrieved or tool-provided content contains untrusted instructions.",
            ), started_at)

        if self._bool_attr(request, "data_poisoning_detected", "poisoned_evidence"):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["data_poisoning_blocks_evidence_use"],
                explanation="Poisoned or tampered evidence cannot be used for verification.",
            ), started_at)

        if self._bool_attr(request, "contains_secret", "secret_detected", "secret_leakage"):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["secret_leakage_blocks_output"],
                explanation="Tool or model output contains secret-like material and must be blocked.",
            ), started_at)

        if self._bool_attr(request, "contains_pii", "pii_detected"):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.REWRITE,
                policy_version=self._settings.policy_version,
                matched_rules=["pii_leakage_requires_redaction"],
                explanation="PII-like output requires redaction before release.",
            ), started_at)

        if self._sandbox_network_not_denied(request, action_name):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                policy_version=self._settings.policy_version,
                matched_rules=["sandbox_network_denied_by_default"],
                explanation="Sandbox network access is denied by default and requires explicit review.",
            ), started_at)

        if self._repo_claim_without_evidence(request, action_name):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["repo_claim_requires_deterministic_evidence"],
                explanation="Repository, test, and build claims require SandboxRun or deterministic evidence.",
            ), started_at)

        if action_name in TOOL_OUTPUT_ACTIONS and self._bool_attr(request, "contradicted", "contradiction_detected"):
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.REWRITE
                if request.risk_level in {RiskLevel.LOW, RiskLevel.MEDIUM}
                else VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["tool_output_contradiction_requires_repair"],
                explanation="Tool output contradicts available evidence and requires repair or block.",
            ), started_at)

        if request.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                policy_version=self._settings.policy_version,
                matched_rules=["high_risk_requires_human_review"],
                explanation="High-risk actions require human review by default.",
            ), started_at)

        if action_name in SENSITIVE_ACTIONS:
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                policy_version=self._settings.policy_version,
                matched_rules=["sensitive_action_requires_human_review"],
                explanation=f"Action '{request.action}' is sensitive.",
            ), started_at)

        if request.attributes.get("source_authority") == "unknown":
            return self._record_response(PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["unknown_source_blocks_policy_claim"],
                explanation="Unknown-authority sources cannot authorize policy claims.",
            ), started_at)

        return self._record_response(PolicyEvaluationResponse(
            trace_id=trace_id,
            allowed=True,
            action=VerdictAction.ALLOW,
            policy_version=self._settings.policy_version,
            matched_rules=["default_allow_low_medium_risk"],
            explanation="No blocking enterprise policy matched.",
        ), started_at)

    def _evaluate_opa(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str,
    ) -> PolicyEvaluationResponse | None:
        if self._opa_evaluator is None:
            return None
        try:
            return self._opa_evaluator.evaluate(request, trace_id=trace_id, tenant_id=tenant_id)
        except OpaPolicyEvaluationError as exc:
            return PolicyEvaluationResponse(
                trace_id=trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                policy_version=self._settings.policy_version,
                matched_rules=["opa_policy_evaluation_failed"],
                explanation=str(exc),
            )

    def _cross_tenant(self, request: PolicyEvaluationRequest, tenant_id: str) -> bool:
        resource_tenant = self._string_attr(request, "resource_tenant_id", "tenant_id")
        return resource_tenant is not None and resource_tenant != tenant_id

    def _sandbox_network_not_denied(self, request: PolicyEvaluationRequest, action_name: str) -> bool:
        if action_name not in {"run_repo_checks", "sandbox.run", "sandbox_run"}:
            return False
        network_policy = self._string_attr(request, "network_policy")
        return network_policy is not None and network_policy != "deny"

    def _repo_claim_without_evidence(self, request: PolicyEvaluationRequest, action_name: str) -> bool:
        claim_surface = self._string_attr(request, "claim_surface")
        if action_name not in REPO_CLAIM_ACTIONS and claim_surface not in {"repo", "test", "build"}:
            return False
        return not self._bool_attr(
            request,
            "has_sandbox_run",
            "has_deterministic_evidence",
            "deterministic_evidence",
        )

    def _bool_attr(self, request: PolicyEvaluationRequest, *names: str) -> bool:
        for name in names:
            value = request.attributes.get(name)
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.strip().lower() in {"1", "true", "yes"}:
                return True
        return False

    def _string_attr(self, request: PolicyEvaluationRequest, *names: str) -> str | None:
        for name in names:
            value = request.attributes.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _record_response(
        self,
        response: PolicyEvaluationResponse,
        started_at: float,
    ) -> PolicyEvaluationResponse:
        if self._metrics is not None:
            self._metrics.record_policy_decision(
                allowed=response.allowed,
                action=response.action.value,
                matched_rules=response.matched_rules,
                duration_seconds=time.perf_counter() - started_at,
            )
        return response
