from __future__ import annotations

import json
import re
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
from hallu_defense.services.content_security import ContentSecurityScanner, ContentThreat
from hallu_defense.services.rate_limit import ToolValidationRateLimiter as ToolValidationRateLimiter

SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|apikey|authorization|credential|password|secret|token)",
    re.I,
)
DANGEROUS_TOOL_RE = re.compile(
    r"(?:delete|deploy|payment|charge|transfer|email|write|shell|exec)",
    re.I,
)
SAFE_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
EMAIL_VALUE_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
SSN_VALUE_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PHONE_VALUE_RE = re.compile(
    r"(?<!\w)(?:\+?1[\s.-]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s.-][2-9]\d{2}[\s.-]\d{4}(?!\w)"
)
PHONE_DIGITS_RE = re.compile(r"\D")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|authorization|credential|password|secret|token)\b"
    r"\s*[:=]\s*['\"]?[^\s,;'\"]{4,}"
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.I),
    re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@"),
    SECRET_ASSIGNMENT_RE,
)
MAX_TOOL_SCHEMA_BYTES = 64 * 1024
MAX_TOOL_SCHEMA_NODES = 4096
SAFE_SIDE_EFFECTS = {"", "none", "no_side_effects", "read", "read_only", "readonly"}
POLICY_CONTEXT_KEYS = {
    "resource_tenant_id",
    "target_tenant_id",
    "side_effects",
    "network_policy",
    "contradicted",
    "contradiction_detected",
    "prompt_injection_detected",
    "indirect_prompt_injection_detected",
    "data_poisoning_detected",
}
FORMAT_CHECKER = FormatChecker()


class ToolPolicyEngine(Protocol):
    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        trace_id: str,
        tenant_id: str = "local-dev",
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
    ) -> None:
        self._policy_engine = policy_engine
        self._content_scanner = content_scanner

    def validate_input(
        self,
        envelope: ToolCallEnvelope,
        *,
        trace_id: str = "tool-validation",
        tenant_id: str = "local-dev",
        approval_granted: bool = False,
    ) -> ToolValidationResponse:
        if SAFE_TOOL_NAME_RE.fullmatch(envelope.tool_name) is None:
            return self._blocked("Tool name is invalid.", trace_id=trace_id)
        schema_failure = self._schema_failure(envelope.input, envelope.tool_schema)
        if schema_failure is not None:
            return self._blocked(schema_failure, trace_id=trace_id)
        context_tenant = envelope.caller_context.get("tenant_id")
        if context_tenant is not None and context_tenant != tenant_id:
            return self._blocked(
                "Tool caller tenant context does not match the request.",
                trace_id=trace_id,
            )

        threats = self._content_scanner.scan_tool_payload(
            envelope.input,
            source_ref=envelope.tool_name,
            pre_tool=True,
        )
        needs_approval = self._requires_approval(envelope)
        effective_risk = (
            RiskLevel.HIGH
            if needs_approval and envelope.risk_level not in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            else envelope.risk_level
        )
        decision = self._policy_decision(
            envelope,
            trace_id=trace_id,
            tenant_id=tenant_id,
            action=self._pre_tool_policy_action(envelope.tool_name),
            risk_level=effective_risk,
            threats=threats,
            approval_granted=approval_granted,
        )
        if decision.action is VerdictAction.REQUIRE_HUMAN_REVIEW or (
            needs_approval and not approval_granted
        ):
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                reason=decision.explanation,
                approval_required=True,
                **self._policy_metadata(decision),
            )
        if not decision.allowed:
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.BLOCK,
                reason=decision.explanation,
                approval_required=False,
                **self._policy_metadata(decision),
            )
        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.ALLOW,
            reason="Tool input passed strict schema, context, side-effect, risk, and policy checks.",
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
        schema_failure = self._schema_failure(envelope.input, envelope.tool_schema)
        if schema_failure is not None:
            return self._blocked(schema_failure, trace_id=trace_id)

        secret_sanitized = self._redact_secrets(envelope.input)
        contains_secret = secret_sanitized != envelope.input
        sanitized = self._redact_pii_output(secret_sanitized)
        contains_pii = sanitized != secret_sanitized
        contradiction = self._contradiction_detected(
            envelope.input,
            envelope.caller_context,
        )
        threats = self._content_scanner.scan_tool_payload(
            envelope.input,
            source_ref=envelope.tool_name,
            pre_tool=False,
        )
        decision = self._policy_decision(
            envelope,
            trace_id=trace_id,
            tenant_id=tenant_id,
            action="validate_tool_output",
            risk_level=envelope.risk_level,
            threats=threats,
            contains_secret=contains_secret,
            contains_pii=contains_pii,
            contradiction=contradiction,
        )

        if contains_secret:
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
                **self._policy_metadata(decision),
            )
        if contains_pii and decision.action is VerdictAction.REWRITE:
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
                **self._policy_metadata(decision),
            )
        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.ALLOW,
            reason="Tool output passed strict schema, leakage, contradiction, unsafe-content, and policy checks.",
            sanitized_output=sanitized,
            **self._policy_metadata(decision),
        )

    def _policy_decision(
        self,
        envelope: ToolCallEnvelope,
        *,
        trace_id: str,
        tenant_id: str,
        action: str,
        risk_level: RiskLevel,
        threats: list[ContentThreat],
        approval_granted: bool = False,
        contains_secret: bool = False,
        contains_pii: bool = False,
        contradiction: bool = False,
    ) -> PolicyEvaluationResponse:
        attributes = {
            key: value
            for key, value in envelope.caller_context.items()
            if key in POLICY_CONTEXT_KEYS
        }
        target_tenant = attributes.get("resource_tenant_id") or attributes.get(
            "target_tenant_id"
        )
        attributes.update(
            {
                "request_tenant_id": tenant_id,
                "tenant_id": tenant_id,
                "resource_tenant_id": target_tenant or tenant_id,
                "risk_level": risk_level.value,
                "contains_secret": contains_secret,
                "contains_pii": contains_pii,
                "contradiction_detected": contradiction,
                **self._content_scanner.threat_attributes(threats),
            }
        )
        if approval_granted:
            attributes["approval_status"] = "approved"
        subject = envelope.caller_context.get("subject")
        return self._policy_engine.evaluate(
            PolicyEvaluationRequest(
                subject=subject if isinstance(subject, str) and subject.strip() else "anonymous",
                action=action,
                resource=f"tool:{envelope.tool_name}",
                risk_level=risk_level,
                attributes=attributes,
            ),
            trace_id=trace_id,
            tenant_id=tenant_id,
        )

    def _schema_failure(
        self,
        payload: Mapping[str, object],
        schema: Mapping[str, object],
    ) -> str | None:
        if not schema:
            return "Tool schema must be a non-empty Draft 2020-12 JSON Schema."
        try:
            encoded = json.dumps(
                schema,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError):
            return "Tool schema is not JSON-serializable."
        if len(encoded) > MAX_TOOL_SCHEMA_BYTES:
            return "Tool schema exceeds the 64 KiB safety limit."
        if not self._schema_structure_is_bounded(schema):
            return "Tool schema is too complex or contains an external reference."
        try:
            Draft202012Validator.check_schema(schema)
            first_error = next(
                Draft202012Validator(
                    schema,
                    format_checker=FORMAT_CHECKER,
                ).iter_errors(payload),
                None,
            )
        except SchemaError:
            return "Tool schema is not a valid Draft 2020-12 JSON Schema."
        except Exception:
            return "Tool schema validation could not be completed safely."
        if first_error is not None:
            return "Tool payload does not conform to its declared JSON Schema."
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

    def _requires_approval(self, envelope: ToolCallEnvelope) -> bool:
        return (
            envelope.approval_required
            or envelope.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            or DANGEROUS_TOOL_RE.search(envelope.tool_name) is not None
            or self._has_side_effects(envelope.caller_context.get("side_effects"))
        )

    def _has_side_effects(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() not in SAFE_SIDE_EFFECTS
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return any(self._has_side_effects(item) for item in value)
        return value is not None

    def _pre_tool_policy_action(self, tool_name: str) -> str:
        normalized = tool_name.strip().lower()
        for token, action in (
            ("delete", "delete"),
            ("deploy", "deploy"),
            ("transfer", "transfer"),
            ("payment", "charge"),
            ("charge", "charge"),
            ("email", "send_email"),
            ("write", "write_file"),
        ):
            if token in normalized:
                return action
        return "validate_tool_call"

    def _redact_secrets(self, payload: Mapping[str, object]) -> dict[str, object]:
        redacted: dict[str, object] = {}
        for key, value in payload.items():
            if SENSITIVE_KEY_RE.search(str(key)) and not self._is_redacted_placeholder(value):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = self._redact_secret_value(value)
        return redacted

    def _redact_secret_value(self, value: object) -> object:
        if isinstance(value, Mapping):
            return self._redact_secrets(value)
        if isinstance(value, list):
            return [self._redact_secret_value(item) for item in value]
        if isinstance(value, str):
            redacted = value
            for pattern in SECRET_VALUE_PATTERNS:
                redacted = pattern.sub("[REDACTED]", redacted)
            return redacted
        return value

    def _redact_pii_output(self, payload: Mapping[str, object]) -> dict[str, object]:
        sanitized: dict[str, object] = {}
        for key, value in payload.items():
            if pii_marker := self._pii_key_marker(str(key)):
                sanitized[str(key)] = self._redact_keyed_pii(value, pii_marker)
            elif isinstance(value, Mapping):
                sanitized[str(key)] = self._redact_pii_output(value)
            elif isinstance(value, list):
                sanitized[str(key)] = [self._redact_pii_value(item) for item in value]
            else:
                sanitized[str(key)] = self._redact_pii_value(value)
        return sanitized

    def _redact_pii_value(self, value: object) -> object:
        if isinstance(value, Mapping):
            return self._redact_pii_output(value)
        if isinstance(value, list):
            return [self._redact_pii_value(item) for item in value]
        if isinstance(value, str):
            return self._redact_pii_text(value)
        return value

    def _redact_keyed_pii(self, value: object, marker: str) -> object:
        if isinstance(value, Mapping):
            return self._redact_pii_output(value)
        if isinstance(value, list):
            return [self._redact_keyed_pii(item, marker) for item in value]
        if isinstance(value, str):
            if marker == "[REDACTED_PHONE]" and not self._looks_like_phone_value(value):
                return self._redact_pii_text(value)
            return marker
        return value

    def _redact_pii_text(self, value: str) -> str:
        redacted = EMAIL_VALUE_RE.sub("[REDACTED_EMAIL]", value)
        redacted = SSN_VALUE_RE.sub("[REDACTED_SSN]", redacted)
        return PHONE_VALUE_RE.sub("[REDACTED_PHONE]", redacted)

    def _pii_key_marker(self, key: str) -> str | None:
        normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        if normalized in {"email", "email_address"} or normalized.endswith("_email"):
            return "[REDACTED_EMAIL]"
        if normalized in {"ssn", "social_security_number"} or normalized.endswith("_ssn"):
            return "[REDACTED_SSN]"
        if normalized in {
            "phone",
            "phone_number",
            "telephone",
            "telephone_number",
            "mobile",
            "cell_phone",
        }:
            return "[REDACTED_PHONE]"
        if normalized.endswith(("_phone", "_phone_number", "_telephone", "_mobile")):
            return "[REDACTED_PHONE]"
        return None

    def _looks_like_phone_value(self, value: str) -> bool:
        digits = PHONE_DIGITS_RE.sub("", value)
        return len(digits) == 10 or (len(digits) == 11 and digits.startswith("1"))

    def _contradiction_detected(
        self,
        payload: Mapping[str, object],
        caller_context: Mapping[str, object],
    ) -> bool:
        for mapping in (payload, caller_context):
            pending: list[object] = [mapping]
            while pending:
                value = pending.pop()
                if isinstance(value, Mapping):
                    for key, item in value.items():
                        normalized_key = str(key).strip().lower()
                        if normalized_key in {"contradicted", "contradiction_detected"} and self._truthy(item):
                            return True
                        if normalized_key == "verdict" and isinstance(item, str) and item.upper() == "CONTRADICTED":
                            return True
                        pending.append(item)
                elif isinstance(value, Sequence) and not isinstance(
                    value,
                    (str, bytes, bytearray),
                ):
                    pending.extend(value)
        return False

    def _truthy(self, value: object) -> bool:
        return value is True or (
            isinstance(value, str) and value.strip().lower() in {"1", "true", "yes"}
        )

    def _is_redacted_placeholder(self, value: object) -> bool:
        return isinstance(value, str) and value.strip().lower() in {
            "[redacted]",
            "<redacted>",
            "<set-at-runtime>",
        }

    def _policy_metadata(
        self,
        decision: PolicyEvaluationResponse,
    ) -> _PolicyMetadata:
        return {
            "trace_id": decision.trace_id,
            "policy_version": decision.policy_version,
            "matched_rules": list(decision.matched_rules),
        }

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
