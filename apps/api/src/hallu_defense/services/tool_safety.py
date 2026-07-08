from __future__ import annotations

import re
from collections.abc import Mapping

from hallu_defense.domain.models import (
    RiskLevel,
    ToolCallEnvelope,
    ToolValidationResponse,
    VerdictAction,
)

SECRET_RE = re.compile(r"(api[_-]?key|secret|token|password)", re.I)
DANGEROUS_TOOL_RE = re.compile(r"(delete|deploy|payment|transfer|email|shell|exec)", re.I)
EMAIL_VALUE_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
SSN_VALUE_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
PHONE_VALUE_RE = re.compile(
    r"(?<!\w)(?:\+?1[\s.-]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[\s.-][2-9]\d{2}[\s.-]\d{4}(?!\w)"
)
PHONE_DIGITS_RE = re.compile(r"\D")


class ToolSafetyService:
    def validate_input(self, envelope: ToolCallEnvelope) -> ToolValidationResponse:
        if (
            envelope.approval_required
            or envelope.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            or DANGEROUS_TOOL_RE.search(envelope.tool_name)
        ):
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.REQUIRE_HUMAN_REVIEW,
                reason="Tool call is high-risk and requires approval.",
                approval_required=True,
            )

        missing = self._required_schema_keys(envelope)
        if missing:
            return ToolValidationResponse(
                allowed=False,
                action=VerdictAction.BLOCK,
                reason=f"Tool input is missing required keys: {', '.join(missing)}.",
            )

        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.ALLOW,
            reason="Tool input passed schema and risk checks.",
            approval_required=False,
        )

    def validate_output(self, envelope: ToolCallEnvelope) -> ToolValidationResponse:
        sanitized = self._redact_sensitive_output(envelope.input)
        changed = sanitized != envelope.input
        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.REWRITE if changed else VerdictAction.ALLOW,
            reason="Tool output was sanitized." if changed else "Tool output passed safety checks.",
            sanitized_output=sanitized,
        )

    def _required_schema_keys(self, envelope: ToolCallEnvelope) -> list[str]:
        required = envelope.tool_schema.get("required", [])
        if not isinstance(required, list):
            return []
        return [key for key in required if isinstance(key, str) and key not in envelope.input]

    def _redact_sensitive_output(self, payload: Mapping[str, object]) -> dict[str, object]:
        sanitized: dict[str, object] = {}
        for key, value in payload.items():
            if SECRET_RE.search(key):
                sanitized[key] = "[REDACTED]"
            elif pii_marker := self._pii_key_marker(key):
                sanitized[key] = self._redact_keyed_pii(value, pii_marker)
            elif isinstance(value, dict):
                sanitized[key] = self._redact_sensitive_output(value)
            elif isinstance(value, list):
                sanitized[key] = [self._redact_value(item) for item in value]
            else:
                sanitized[key] = self._redact_value(value)
        return sanitized

    def _redact_value(self, value: object) -> object:
        if isinstance(value, dict):
            return self._redact_sensitive_output(value)
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, str):
            return self._redact_pii_text(value)
        return value

    def _redact_keyed_pii(self, value: object, marker: str) -> object:
        if isinstance(value, dict):
            return self._redact_sensitive_output(value)
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
        if normalized in {"phone", "phone_number", "telephone", "telephone_number", "mobile", "cell_phone"}:
            return "[REDACTED_PHONE]"
        if normalized.endswith(("_phone", "_phone_number", "_telephone", "_mobile")):
            return "[REDACTED_PHONE]"
        return None

    def _looks_like_phone_value(self, value: str) -> bool:
        digits = PHONE_DIGITS_RE.sub("", value)
        return len(digits) == 10 or (len(digits) == 11 and digits.startswith("1"))
