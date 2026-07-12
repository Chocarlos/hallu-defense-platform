from __future__ import annotations

import time
import unicodedata
from dataclasses import dataclass
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

VERIFIED_POLICY_CONTEXT_VERSION = "verified-policy-context.v1"
PUBLIC_POLICY_DEFINITION_VERSION = "public-policy-actions.v1"
SENSITIVE_ACTIONS = frozenset(
    {"delete", "deploy", "send_email", "transfer", "charge", "write_file"}
)
REPO_CLAIM_ACTIONS = frozenset(
    {"verify_build_claim", "verify_repo_claim", "verify_test_claim"}
)
TOOL_OUTPUT_ACTIONS = frozenset(
    {"publish_output", "tool_output", "validate_output", "validate_tool_output"}
)
SANDBOX_ACTIONS = frozenset({"run_repo_checks", "sandbox.run", "sandbox_run"})
KNOWN_POLICY_ACTIONS = frozenset(
    {
        "charge",
        "delete",
        "deploy",
        "publish_output",
        "read",
        "retrieve_evidence",
        "run_repo_checks",
        "sandbox.run",
        "sandbox_run",
        "send_email",
        "tool_output",
        "transfer",
        "validate_output",
        "validate_tool_call",
        "validate_tool_output",
        "verify_build_claim",
        "verify_repo_claim",
        "verify_response",
        "verify_test_claim",
        "write_file",
    }
)
KNOWN_SOURCE_AUTHORITIES = frozenset(
    {"authoritative", "external", "internal", "unknown", "untrusted"}
)


def _normalized_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = "".join(
        character
        for character in unicodedata.normalize("NFKC", value).strip()
        if unicodedata.category(character) != "Cf"
    )
    return normalized or None


def _normalized_name(value: object) -> str:
    normalized = _normalized_text(value)
    return normalized.casefold() if normalized is not None else ""


def _restrictive_bool(attributes: dict[str, object], *names: str) -> bool:
    for name in names:
        value = attributes.get(name)
        if value is True:
            return True
        if isinstance(value, str) and value.strip().casefold() in {"1", "true", "yes"}:
            return True
    return False


@dataclass(frozen=True, slots=True)
class VerifiedPolicyContext:
    """Server-built policy facts; callers cannot assert authorization evidence."""

    tenant_id: str
    subject_id: str
    action: str
    resource: str
    resource_tenant_id: str
    risk_level: RiskLevel
    definition_known: bool
    definition_version: str
    approval_required_for_action: bool = True
    approval_granted: bool = False
    approval_binding_valid: bool = False
    approval_id: str | None = None
    prompt_injection_detected: bool = False
    indirect_prompt_injection_detected: bool = False
    data_poisoning_detected: bool = False
    contains_secret: bool = False
    contains_pii: bool = False
    contradiction_detected: bool = False
    source_authority: str | None = None
    network_policy: str = "deny"
    claim_surface: str | None = None
    deterministic_evidence_verified: bool = False
    context_version: str = VERIFIED_POLICY_CONTEXT_VERSION

    @classmethod
    def from_public_request(
        cls,
        request: PolicyEvaluationRequest,
        *,
        tenant_id: str,
        subject_id: str | None,
    ) -> VerifiedPolicyContext:
        """Convert a public simulation request to restrictive, non-authorizing facts."""

        attributes = request.attributes
        action = _normalized_name(request.action)
        resource_tenant = _normalized_text(attributes.get("resource_tenant_id")) or tenant_id
        network_policy = _normalized_name(attributes.get("network_policy")) or "deny"
        if network_policy not in {"deny", "allowlisted"}:
            network_policy = "untrusted"
        requested_source_authority = _normalized_name(
            attributes.get("source_authority")
        )
        # A public simulation may make the request more restrictive, but it
        # cannot self-assert positive source provenance.
        source_authority = (
            "unknown" if requested_source_authority == "unknown" else None
        )
        claim_surface = _normalized_name(attributes.get("claim_surface")) or None
        if claim_surface not in {None, "repo", "test", "build"}:
            claim_surface = "unknown"
        return cls(
            tenant_id=tenant_id,
            subject_id=(
                _normalized_text(subject_id)
                or _normalized_text(request.subject)
                or "anonymous"
            ),
            action=action,
            resource=_normalized_text(request.resource) or "",
            resource_tenant_id=resource_tenant,
            risk_level=request.risk_level,
            definition_known=action in KNOWN_POLICY_ACTIONS,
            definition_version=(PUBLIC_POLICY_DEFINITION_VERSION if action in KNOWN_POLICY_ACTIONS else ""),
            # These signals only make the public request more restrictive. In
            # particular, approval and deterministic-evidence assertions are
            # deliberately ignored here.
            prompt_injection_detected=_restrictive_bool(
                attributes, "prompt_injection_detected", "prompt_injection"
            ),
            indirect_prompt_injection_detected=_restrictive_bool(
                attributes,
                "indirect_prompt_injection_detected",
                "indirect_prompt_injection",
            ),
            data_poisoning_detected=_restrictive_bool(
                attributes, "data_poisoning_detected", "poisoned_evidence"
            ),
            contains_secret=_restrictive_bool(
                attributes, "contains_secret", "secret_detected", "secret_leakage"
            ),
            contains_pii=_restrictive_bool(attributes, "contains_pii", "pii_detected"),
            contradiction_detected=_restrictive_bool(
                attributes, "contradicted", "contradiction_detected"
            ),
            source_authority=source_authority,
            network_policy=network_policy,
            claim_surface=claim_surface,
        )

    @property
    def approval_is_verified(self) -> bool:
        return self.approval_granted and self.approval_binding_valid

    def is_valid(self) -> bool:
        """Reject malformed internal facts before either policy backend sees them."""

        canonical_identities = (
            self.tenant_id,
            self.subject_id,
            self.resource_tenant_id,
        )
        if any(
            not isinstance(value, str)
            or _normalized_text(value) != value
            or len(value) > 256
            for value in canonical_identities
        ):
            return False
        if (
            not isinstance(self.action, str)
            or not self.action
            or _normalized_name(self.action) != self.action
            or len(self.action) > 128
        ):
            return False
        if (
            not isinstance(self.resource, str)
            or len(self.resource) > 512
            or (self.resource and _normalized_text(self.resource) != self.resource)
        ):
            return False
        if type(self.risk_level) is not RiskLevel:
            return False
        if type(self.definition_known) is not bool:
            return False
        if (
            not isinstance(self.definition_version, str)
            or len(self.definition_version) > 128
            or (
                self.definition_version
                and _normalized_text(self.definition_version) != self.definition_version
            )
        ):
            return False
        boolean_facts = (
            self.approval_required_for_action,
            self.approval_granted,
            self.approval_binding_valid,
            self.prompt_injection_detected,
            self.indirect_prompt_injection_detected,
            self.data_poisoning_detected,
            self.contains_secret,
            self.contains_pii,
            self.contradiction_detected,
            self.deterministic_evidence_verified,
        )
        if any(type(value) is not bool for value in boolean_facts):
            return False
        if self.approval_id is not None and (
            not isinstance(self.approval_id, str)
            or _normalized_text(self.approval_id) != self.approval_id
            or len(self.approval_id) > 256
        ):
            return False
        if self.approval_is_verified and self.approval_id is None:
            return False
        if self.source_authority is not None and (
            not isinstance(self.source_authority, str)
            or _normalized_name(self.source_authority) != self.source_authority
            or len(self.source_authority) > 128
            or self.source_authority not in KNOWN_SOURCE_AUTHORITIES
        ):
            return False
        if self.claim_surface not in {None, "repo", "test", "build", "unknown"}:
            return False
        if self.network_policy not in {"deny", "allowlisted", "untrusted"}:
            return False
        return self.context_version == VERIFIED_POLICY_CONTEXT_VERSION

    def matches_request(
        self,
        request: PolicyEvaluationRequest,
        *,
        tenant_id: str,
        subject_id: str | None,
    ) -> bool:
        if not self.is_valid():
            return False
        if self.tenant_id != tenant_id:
            return False
        if self.action != _normalized_name(request.action):
            return False
        if self.resource != (_normalized_text(request.resource) or ""):
            return False
        if self.risk_level is not request.risk_level:
            return False
        if subject_id is not None:
            expected_subject = _normalized_text(subject_id)
            if expected_subject is None:
                return False
        else:
            expected_subject = _normalized_text(request.subject) or "anonymous"
        return self.subject_id == expected_subject

    def to_opa_input(self) -> dict[str, object]:
        return {
            "verified": {
                "context_version": self.context_version,
                "identity": {
                    "tenant_id": self.tenant_id,
                    "subject_id": self.subject_id,
                },
                "request": {
                    "action": self.action,
                    "resource": self.resource,
                    "risk_level": self.risk_level.value,
                },
                "resource": {"tenant_id": self.resource_tenant_id},
                "definition": {
                    "known": self.definition_known,
                    "version": self.definition_version,
                },
                "approval": {
                    "required_for_action": self.approval_required_for_action,
                    "granted": self.approval_granted,
                    "binding_valid": self.approval_binding_valid,
                    "approval_id": self.approval_id or "",
                },
                "signals": {
                    "prompt_injection_detected": self.prompt_injection_detected,
                    "indirect_prompt_injection_detected": self.indirect_prompt_injection_detected,
                    "data_poisoning_detected": self.data_poisoning_detected,
                    "contains_secret": self.contains_secret,
                    "contains_pii": self.contains_pii,
                    "contradiction_detected": self.contradiction_detected,
                    "source_authority": self.source_authority or "",
                    "claim_surface": self.claim_surface or "",
                },
                "sandbox": {"network_policy": self.network_policy},
                "evidence": {
                    "deterministic_verified": self.deterministic_evidence_verified,
                },
            }
        }


class PolicyEvaluator(Protocol):
    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str,
        *,
        verified_context: VerifiedPolicyContext,
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
        *,
        subject_id: str | None = None,
        verified_context: VerifiedPolicyContext | None = None,
    ) -> PolicyEvaluationResponse:
        started_at = time.perf_counter()
        context = verified_context or VerifiedPolicyContext.from_public_request(
            request,
            tenant_id=tenant_id,
            subject_id=subject_id,
        )
        if not context.matches_request(
            request,
            tenant_id=tenant_id,
            subject_id=subject_id,
        ):
            return self._record_response(
                self._block(
                    trace_id,
                    "invalid_verified_policy_context",
                    "Verified policy context is missing or malformed.",
                ),
                started_at,
            )

        opa_response = self._evaluate_opa(request, trace_id, tenant_id, context)
        if opa_response is not None:
            return self._record_response(opa_response, started_at)

        return self._record_response(self._evaluate_python(context, trace_id), started_at)

    def _evaluate_python(
        self,
        context: VerifiedPolicyContext,
        trace_id: str,
    ) -> PolicyEvaluationResponse:
        if context.action not in KNOWN_POLICY_ACTIONS:
            return self._block(
                trace_id,
                "unknown_policy_action_blocked",
                "Unknown policy actions are blocked until registered server-side.",
            )
        if not context.definition_known or not context.definition_version:
            return self._block(
                trace_id,
                "unknown_tool_definition_blocked",
                "Tool definition is unknown or unversioned.",
            )
        if context.resource_tenant_id != context.tenant_id:
            return self._block(
                trace_id,
                "cross_tenant_access_denied",
                "Request tenant does not match the target resource tenant.",
            )
        if context.prompt_injection_detected:
            return self._block(
                trace_id,
                "prompt_injection_blocks_untrusted_instruction",
                "Prompt injection attempts cannot override system or policy instructions.",
            )
        if context.indirect_prompt_injection_detected:
            return self._block(
                trace_id,
                "indirect_prompt_injection_blocks_document_instruction",
                "Retrieved or tool-provided content contains untrusted instructions.",
            )
        if context.data_poisoning_detected:
            return self._block(
                trace_id,
                "data_poisoning_blocks_evidence_use",
                "Poisoned or tampered evidence cannot be used for verification.",
            )
        if context.contains_secret:
            return self._block(
                trace_id,
                "secret_leakage_blocks_output",
                "Tool or model output contains secret-like material and must be blocked.",
            )
        if (
            context.action in SANDBOX_ACTIONS
            and context.network_policy not in {"deny", "allowlisted"}
        ):
            return self._block(
                trace_id,
                "sandbox_network_policy_invalid",
                "Sandbox network policy is invalid.",
            )
        if (
            context.action in REPO_CLAIM_ACTIONS
            or context.claim_surface in {"repo", "test", "build"}
        ) and not context.deterministic_evidence_verified:
            return self._block(
                trace_id,
                "repo_claim_requires_deterministic_evidence",
                "Repository, test, and build claims require verified SandboxRun or command evidence.",
            )
        if (
            context.action in TOOL_OUTPUT_ACTIONS
            and context.contradiction_detected
            and context.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        ):
            return self._decision(
                trace_id,
                allowed=False,
                action=VerdictAction.BLOCK,
                rule="tool_output_contradiction_requires_repair",
                explanation="Tool output contradicts available evidence and requires repair or block.",
            )
        if context.source_authority == "unknown":
            return self._block(
                trace_id,
                "unknown_source_blocks_policy_claim",
                "Unknown-authority sources cannot authorize policy claims.",
            )
        if context.action in TOOL_OUTPUT_ACTIONS and context.contradiction_detected:
            return self._decision(
                trace_id,
                allowed=False,
                action=VerdictAction.REWRITE,
                rule="tool_output_contradiction_requires_repair",
                explanation="Tool output contradicts available evidence and requires repair or block.",
            )
        if context.contains_pii:
            return self._decision(
                trace_id,
                allowed=False,
                action=VerdictAction.REWRITE,
                rule="pii_leakage_requires_redaction",
                explanation="PII-like output requires redaction before release.",
            )
        if (
            context.action in SANDBOX_ACTIONS
            and context.network_policy == "allowlisted"
            and not context.approval_is_verified
        ):
            return self._decision(
                trace_id,
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                rule="sandbox_network_denied_by_default",
                explanation="Sandbox network access is denied by default and requires explicit review.",
            )
        if (
            context.approval_required_for_action
            and context.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            and not context.approval_is_verified
        ):
            return self._review(
                trace_id,
                "high_risk_requires_human_review",
                "High-risk actions require a bound human approval.",
            )
        if context.action in SENSITIVE_ACTIONS and not context.approval_is_verified:
            return self._review(
                trace_id,
                "sensitive_action_requires_human_review",
                "Sensitive actions require human review before execution.",
            )
        if context.action in SANDBOX_ACTIONS and context.network_policy == "deny":
            return self._decision(
                trace_id,
                allowed=True,
                action=VerdictAction.ALLOW,
                rule="sandbox_network_policy_deny_by_default",
                explanation="Sandbox network policy defaults to deny.",
            )
        return self._decision(
            trace_id,
            allowed=True,
            action=VerdictAction.ALLOW,
            rule="default_allow_registered_action",
            explanation="No blocking enterprise policy matched the registered action.",
        )

    def _evaluate_opa(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str,
        context: VerifiedPolicyContext,
    ) -> PolicyEvaluationResponse | None:
        if self._opa_evaluator is None:
            if self._settings.opa_enabled:
                return self._opa_failure_response(trace_id)
            return None
        try:
            response = self._opa_evaluator.evaluate(
                request,
                trace_id=trace_id,
                tenant_id=tenant_id,
                verified_context=context,
            )
        except (OpaPolicyEvaluationError, TypeError):
            return self._opa_failure_response(trace_id)
        if response is None and self._settings.opa_enabled:
            return self._opa_failure_response(trace_id)
        return response

    def _opa_failure_response(self, trace_id: str) -> PolicyEvaluationResponse:
        return self._block(
            trace_id,
            "opa_policy_evaluation_failed",
            "OPA policy evaluation failed closed.",
        )

    def _block(self, trace_id: str, rule: str, explanation: str) -> PolicyEvaluationResponse:
        return self._decision(
            trace_id,
            allowed=False,
            action=VerdictAction.BLOCK,
            rule=rule,
            explanation=explanation,
        )

    def _review(self, trace_id: str, rule: str, explanation: str) -> PolicyEvaluationResponse:
        return self._decision(
            trace_id,
            allowed=False,
            action=VerdictAction.REQUIRE_HUMAN_REVIEW,
            rule=rule,
            explanation=explanation,
        )

    def _decision(
        self,
        trace_id: str,
        *,
        allowed: bool,
        action: VerdictAction,
        rule: str,
        explanation: str,
    ) -> PolicyEvaluationResponse:
        return PolicyEvaluationResponse(
            trace_id=trace_id,
            allowed=allowed,
            action=action,
            policy_version=self._settings.policy_version,
            matched_rules=[rule],
            explanation=explanation,
        )

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
