from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Protocol, TypedDict

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from hallu_defense.domain.models import (
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    RiskLevel,
    ToolCallEnvelope,
    ToolValidationResponse,
    VerdictAction,
)
from hallu_defense.services.content_security import (
    ContentSecurityScanner,
    ContentThreat,
    SensitiveDataRedactor,
)
from hallu_defense.services.approvals import (
    ApprovalAuthorizationIssuer,
    ConsumedApprovalAuthorization,
)
from hallu_defense.services.policy import VerifiedPolicyContext
from hallu_defense.services.rate_limit import ToolValidationRateLimiter as ToolValidationRateLimiter
from hallu_defense.services.tool_definitions import (
    ToolDefinitionError,
    TrustedToolBinding,
    TrustedToolRegistry,
    canonical_json_dumps,
)

MAX_TOOL_SCHEMA_BYTES = 64 * 1024
MAX_TOOL_SCHEMA_NODES = 4096
MAX_CONTRADICTION_SCAN_NODES = 4096
MAX_CONTRADICTION_SCAN_DEPTH = 32
FORMAT_CHECKER = FormatChecker()


class ToolPolicyEngine(Protocol):
    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str = "local-dev",
        *,
        subject_id: str | None = None,
        verified_context: VerifiedPolicyContext | None = None,
    ) -> PolicyEvaluationResponse: ...


class _PolicyMetadata(TypedDict):
    trace_id: str
    policy_version: str
    matched_rules: list[str]


class ToolSafetyService:
    def __init__(
        self,
        *,
        policy_engine: ToolPolicyEngine,
        content_scanner: ContentSecurityScanner,
        tool_registry: TrustedToolRegistry | None = None,
        redactor: SensitiveDataRedactor | None = None,
        authorization_issuer: ApprovalAuthorizationIssuer | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._content_scanner = content_scanner
        self._tool_registry = tool_registry or TrustedToolRegistry.default()
        self._redactor = redactor or SensitiveDataRedactor()
        self._authorization_issuer = authorization_issuer or ApprovalAuthorizationIssuer()

    def validate_input(
        self,
        envelope: ToolCallEnvelope,
        *,
        trace_id: str = "tool-validation",
        tenant_id: str = "local-dev",
        approval_authorization: ConsumedApprovalAuthorization | None = None,
    ) -> ToolValidationResponse:
        resolved = self._resolve(envelope, phase="input", trace_id=trace_id)
        if isinstance(resolved, ToolValidationResponse):
            return resolved
        canonical, binding = resolved

        schema_failure = self._schema_failure(canonical.input, binding.input_schema)
        if schema_failure is not None:
            return self._blocked(schema_failure, trace_id=trace_id)
        context_tenant = canonical.caller_context.get("tenant_id")
        if context_tenant is not None and context_tenant != tenant_id:
            return self._blocked(
                "Tool caller tenant context does not match the request.",
                trace_id=trace_id,
            )

        threats = self._content_scanner.scan_tool_payload(
            canonical.input,
            source_ref=canonical.tool_name,
            pre_tool=True,
        )
        needs_approval = (
            binding.approval_required
            or binding.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            or bool(binding.side_effects)
        )
        subject = self._context_text(canonical.caller_context.get("subject")) or "anonymous"
        approval_verified = self._approval_is_verified(
            canonical,
            binding=binding,
            tenant_id=tenant_id,
            subject_id=subject,
            authorization=approval_authorization,
        )
        if approval_authorization is not None and not approval_verified:
            return self._blocked(
                "Approval authorization capability is invalid for this tool call.",
                trace_id=trace_id,
            )
        decision = self._policy_decision(
            canonical,
            binding=binding,
            trace_id=trace_id,
            tenant_id=tenant_id,
            action=binding.policy_action,
            risk_level=binding.risk_level,
            threats=threats,
            approval_required_for_action=needs_approval,
            approval_verified=approval_verified,
        )
        if not decision.allowed and decision.action is not VerdictAction.REQUIRE_HUMAN_REVIEW:
            return ToolValidationResponse(
                allowed=False,
                action=decision.action,
                reason=decision.explanation,
                approval_required=False,
                **self._policy_metadata(decision),
            )
        if decision.action is VerdictAction.REQUIRE_HUMAN_REVIEW or (
            needs_approval and not approval_verified
        ):
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                reason=decision.explanation,
                approval_required=True,
                **self._policy_metadata(decision),
            )
        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.ALLOW,
            reason="Tool input passed its trusted schema, identity, side-effect, risk, and policy checks.",
            approval_required=False,
            **self._policy_metadata(decision),
        )

    def validate_output(
        self,
        envelope: ToolCallEnvelope,
        *,
        trace_id: str = "tool-validation",
        tenant_id: str = "local-dev",
    ) -> ToolValidationResponse:
        resolved = self._resolve(envelope, phase="output", trace_id=trace_id)
        if isinstance(resolved, ToolValidationResponse):
            return resolved
        canonical, binding = resolved
        schema_failure = self._schema_failure(canonical.input, binding.output_schema)
        if schema_failure is not None:
            return self._blocked(schema_failure, trace_id=trace_id)

        redaction = self._redactor.redact(canonical.input)
        if not redaction.complete or not isinstance(redaction.value, dict):
            return self._blocked(
                "Tool output could not be redacted within the safety limits.",
                trace_id=trace_id,
            )
        sanitized = redaction.value
        if redaction.secret_found and not self._sanitized_output_is_stable(sanitized):
            return self._blocked(
                "Tool output credentials could not be removed completely.",
                trace_id=trace_id,
            )
        sanitized_schema_failure = self._schema_failure(
            sanitized,
            binding.output_schema,
        )
        if sanitized_schema_failure is not None:
            return self._blocked(
                "Sanitized tool output does not conform to its trusted JSON Schema.",
                trace_id=trace_id,
            )
        contradiction = self._contradiction_detected(
            canonical.input,
        )
        threats = self._content_scanner.scan_tool_payload(
            canonical.input,
            source_ref=canonical.tool_name,
            pre_tool=False,
        )
        decision = self._policy_decision(
            canonical,
            binding=binding,
            trace_id=trace_id,
            tenant_id=tenant_id,
            action="validate_tool_output",
            risk_level=binding.risk_level,
            threats=threats,
            # Output validation never requests a second execution approval.
            approval_required_for_action=False,
            contains_secret=redaction.secret_found,
            contains_pii=redaction.pii_found,
            contradiction=contradiction,
        )

        if redaction.secret_found:
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.BLOCK,
                reason=decision.explanation,
                sanitized_output=sanitized,
                **self._policy_metadata(decision),
            )
        if threats:
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.BLOCK,
                reason=decision.explanation,
                sanitized_output=sanitized,
                **self._policy_metadata(decision),
            )
        if contradiction:
            return ToolValidationResponse(
                allowed=False,
                action=(
                    decision.action
                    if decision.action in {VerdictAction.REWRITE, VerdictAction.BLOCK}
                    else VerdictAction.BLOCK
                ),
                reason=decision.explanation,
                sanitized_output=sanitized,
                **self._policy_metadata(decision),
            )
        if redaction.pii_found and decision.action is VerdictAction.REWRITE:
            return ToolValidationResponse(
                allowed=True,
                action=VerdictAction.REWRITE,
                reason="Tool output PII was redacted according to policy.",
                sanitized_output=sanitized,
                **self._policy_metadata(decision),
            )
        if not decision.allowed:
            return ToolValidationResponse(
                allowed=False,
                action=decision.action,
                reason=decision.explanation,
                sanitized_output=sanitized,
                **self._policy_metadata(decision),
            )
        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.ALLOW,
            reason="Tool output passed its trusted schema, leakage, contradiction, and policy checks.",
            sanitized_output=sanitized,
            **self._policy_metadata(decision),
        )

    def _resolve(
        self,
        envelope: ToolCallEnvelope,
        *,
        phase: str,
        trace_id: str,
    ) -> tuple[ToolCallEnvelope, TrustedToolBinding] | ToolValidationResponse:
        try:
            canonical = self._tool_registry.bind(
                envelope,
                phase="input" if phase == "input" else "output",
            )
            return canonical, self._tool_registry.verify_binding(canonical)
        except ToolDefinitionError:
            return self._blocked(
                "Tool definition is unknown or public metadata does not match the trusted server definition.",
                trace_id=trace_id,
            )

    def _policy_decision(
        self,
        envelope: ToolCallEnvelope,
        *,
        binding: TrustedToolBinding,
        trace_id: str,
        tenant_id: str,
        action: str,
        risk_level: RiskLevel,
        threats: list[ContentThreat],
        approval_required_for_action: bool,
        approval_verified: bool = False,
        contains_secret: bool = False,
        contains_pii: bool = False,
        contradiction: bool = False,
    ) -> PolicyEvaluationResponse:
        subject = self._context_text(envelope.caller_context.get("subject")) or "anonymous"
        resource = f"tool:{binding.tool_name}"
        request = PolicyEvaluationRequest(
            subject=subject,
            action=action,
            resource=resource,
            risk_level=risk_level,
            attributes={},
        )
        threat_types = {threat.threat_type for threat in threats}
        context = VerifiedPolicyContext(
            tenant_id=tenant_id,
            subject_id=subject,
            action=action,
            resource=resource,
            resource_tenant_id=tenant_id,
            risk_level=risk_level,
            definition_known=True,
            definition_version=binding.definition_version,
            approval_required_for_action=approval_required_for_action,
            approval_granted=approval_verified,
            approval_binding_valid=approval_verified,
            approval_id=envelope.approval_id if approval_verified else None,
            prompt_injection_detected="prompt_injection" in threat_types,
            indirect_prompt_injection_detected="indirect_prompt_injection" in threat_types,
            data_poisoning_detected="data_poisoning" in threat_types,
            contains_secret=contains_secret,
            contains_pii=contains_pii,
            contradiction_detected=contradiction,
            source_authority=None,
            network_policy="deny",
            claim_surface=None,
        )
        return self._policy_engine.evaluate(
            request,
            trace_id=trace_id,
            tenant_id=tenant_id,
            subject_id=subject,
            verified_context=context,
        )

    def _approval_is_verified(
        self,
        envelope: ToolCallEnvelope,
        *,
        binding: TrustedToolBinding,
        tenant_id: str,
        subject_id: str,
        authorization: ConsumedApprovalAuthorization | None,
    ) -> bool:
        if authorization is None or not self._authorization_issuer.consume(
            authorization
        ):
            return False
        approved = authorization.binding
        arguments_hash = "sha256:" + hashlib.sha256(
            canonical_json_dumps(envelope.input).encode("utf-8")
        ).hexdigest()
        return (
            envelope.approval_id == authorization.approval_id
            and approved.approval_id == authorization.approval_id
            and bool(approved.origin_trace_id)
            and bool(envelope.approval_execution_token)
            and approved.tenant_id == tenant_id
            and approved.subject_id == subject_id
            and approved.tool_name == binding.tool_name
            and approved.policy_action == binding.policy_action
            and hmac.compare_digest(approved.arguments_hash, arguments_hash)
            and approved.definition_version == binding.definition_version
            and hmac.compare_digest(
                approved.definition_digest,
                binding.definition_digest,
            )
        )

    def _schema_failure(
        self,
        payload: Mapping[str, object],
        schema: Mapping[str, object],
    ) -> str | None:
        if not schema:
            return "Trusted tool schema must be a non-empty Draft 2020-12 JSON Schema."
        try:
            encoded = json.dumps(
                schema,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError):
            return "Trusted tool schema is not JSON-serializable."
        if len(encoded) > MAX_TOOL_SCHEMA_BYTES:
            return "Trusted tool schema exceeds the 64 KiB safety limit."
        if not self._schema_structure_is_bounded(schema):
            return "Trusted tool schema is too complex or contains an external reference."
        try:
            Draft202012Validator.check_schema(schema)
            first_error = next(
                Draft202012Validator(schema, format_checker=FORMAT_CHECKER).iter_errors(payload),
                None,
            )
        except SchemaError:
            return "Trusted tool schema is not a valid Draft 2020-12 JSON Schema."
        except Exception:
            return "Trusted tool schema validation could not be completed safely."
        if first_error is not None:
            return "Tool payload does not conform to its trusted JSON Schema."
        return None

    def _schema_structure_is_bounded(self, schema: Mapping[str, object]) -> bool:
        pending: list[object] = [schema]
        nodes = 0
        while pending:
            value = pending.pop()
            nodes += 1
            if nodes > MAX_TOOL_SCHEMA_NODES:
                return False
            if isinstance(value, Mapping):
                for key, item in value.items():
                    if key in {"$ref", "$dynamicRef"} and (
                        not isinstance(item, str) or not item.startswith("#")
                    ):
                        return False
                    pending.append(item)
            elif isinstance(value, Sequence) and not isinstance(
                value,
                (str, bytes, bytearray),
            ):
                pending.extend(value)
        return True

    def _contradiction_detected(self, *roots: Mapping[str, object]) -> bool:
        pending: list[tuple[object, int]] = [(root, 0) for root in roots]
        visited: set[int] = set()
        nodes = 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if nodes > MAX_CONTRADICTION_SCAN_NODES or depth > MAX_CONTRADICTION_SCAN_DEPTH:
                return True
            if isinstance(value, Mapping):
                identity = id(value)
                if identity in visited:
                    return True
                visited.add(identity)
                for key, item in value.items():
                    normalized_key = self._context_name(str(key)) or ""
                    if normalized_key in {"contradicted", "contradiction_detected"} and self._truthy(item):
                        return True
                    if normalized_key == "verdict" and isinstance(item, str) and item.strip().upper() == "CONTRADICTED":
                        return True
                    pending.append((item, depth + 1))
            elif isinstance(value, Sequence) and not isinstance(
                value,
                (str, bytes, bytearray),
            ):
                identity = id(value)
                if identity in visited:
                    return True
                visited.add(identity)
                pending.extend((item, depth + 1) for item in value)
        return False

    @staticmethod
    def _context_text(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = "".join(
            character
            for character in unicodedata.normalize("NFKC", value).strip()
            if unicodedata.category(character) != "Cf"
        )
        return normalized or None

    @classmethod
    def _context_name(cls, value: object) -> str | None:
        text = cls._context_text(value)
        return text.casefold() if text is not None else None

    @staticmethod
    def _truthy(value: object) -> bool:
        return value is True or (
            isinstance(value, str) and value.strip().casefold() in {"1", "true", "yes"}
        )

    def _policy_metadata(
        self,
        decision: PolicyEvaluationResponse,
    ) -> _PolicyMetadata:
        return {
            "trace_id": decision.trace_id,
            "policy_version": decision.policy_version,
            "matched_rules": list(decision.matched_rules),
        }

    def _sanitized_output_is_stable(self, value: dict[str, object]) -> bool:
        verification = self._redactor.redact(value)
        return (
            verification.complete
            and not verification.secret_found
            and verification.value == value
        )

    def _blocked(
        self,
        reason: str,
        *,
        trace_id: str,
    ) -> ToolValidationResponse:
        return ToolValidationResponse(
            allowed=False,
            action=VerdictAction.BLOCK,
            reason=reason,
            approval_required=False,
            trace_id=trace_id,
        )
