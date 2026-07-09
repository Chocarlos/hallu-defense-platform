from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass

ANONYMOUS_SUBJECT = "anonymous"
ADMIN_ROLE = "admin"
APPROVAL_REVIEWER_ROLE = "approval_reviewer"
AUDITOR_ROLE = "auditor"
EVAL_PUBLISHER_ROLE = "eval_publisher"
METRICS_READER_ROLE = "metrics_reader"
POLICY_EVALUATOR_ROLE = "policy_evaluator"
RAG_WRITER_ROLE = "rag_writer"
SANDBOX_RUNNER_ROLE = "sandbox_runner"
TOOL_OPERATOR_ROLE = "tool_operator"
VERIFIER_ROLE = "verifier"
AUTH_CLAIMS_MODE_UNSIGNED_HEADERS = "unsigned_headers"
AUTH_CLAIMS_MODE_SIGNED_HEADERS = "signed_headers"
TRUSTED_HEADER_SIGNATURE_VERSION = "v1"
ROLE_SPLIT_RE = re.compile(r"[\s,]+")


class AuthenticationError(RuntimeError):
    pass


class AuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Principal:
    subject_id: str
    roles: frozenset[str]

    @property
    def is_authenticated(self) -> bool:
        return self.subject_id != ANONYMOUS_SUBJECT

    def has_role(self, role: str) -> bool:
        return role in self.roles or ADMIN_ROLE in self.roles

    def require_role(self, role: str) -> None:
        self.require_any_role(frozenset({role}))

    def require_any_role(self, roles: frozenset[str]) -> None:
        if not self.is_authenticated:
            raise AuthorizationError("Authenticated principal is required.")
        if not roles:
            raise AuthorizationError("At least one required role must be configured.")
        if not any(self.has_role(role) for role in roles):
            required = ", ".join(sorted(roles))
            raise AuthorizationError(f"Principal is missing one of required roles: {required}.")


def principal_from_headers(
    *,
    tenant_id: str | None = None,
    subject_id: str | None,
    roles_header: str | None,
    authorization: str | None,
    auth_required: bool,
    claims_mode: str = AUTH_CLAIMS_MODE_UNSIGNED_HEADERS,
    claims_signature: str | None = None,
    claims_timestamp: str | None = None,
    signature_secret: str | None = None,
    signature_tolerance_seconds: int = 300,
    current_time_seconds: int | None = None,
) -> Principal:
    normalized_claims_mode = claims_mode.strip().lower()
    if normalized_claims_mode not in {
        AUTH_CLAIMS_MODE_UNSIGNED_HEADERS,
        AUTH_CLAIMS_MODE_SIGNED_HEADERS,
    }:
        raise AuthenticationError(f"Unsupported auth claims mode: {claims_mode}.")

    if auth_required and not _has_text(authorization):
        raise AuthenticationError("Authorization header is required when auth is enabled.")

    normalized_subject = subject_id.strip() if subject_id is not None else ""
    if auth_required and not normalized_subject:
        raise AuthenticationError("Authenticated subject header is required when auth is enabled.")

    if not normalized_subject:
        return Principal(subject_id=ANONYMOUS_SUBJECT, roles=frozenset())

    if normalized_claims_mode == AUTH_CLAIMS_MODE_SIGNED_HEADERS:
        verify_trusted_header_signature(
            tenant_id=tenant_id,
            subject_id=normalized_subject,
            roles_header=roles_header,
            claims_signature=claims_signature,
            claims_timestamp=claims_timestamp,
            signature_secret=signature_secret,
            signature_tolerance_seconds=signature_tolerance_seconds,
            current_time_seconds=current_time_seconds,
        )

    return Principal(
        subject_id=normalized_subject,
        roles=frozenset(_parse_roles(roles_header)),
    )


def sign_trusted_headers(
    *,
    tenant_id: str | None,
    subject_id: str,
    roles_header: str | None,
    claims_timestamp: str,
    signature_secret: str,
) -> str:
    canonical = _canonical_claims_payload(
        tenant_id=tenant_id,
        subject_id=subject_id,
        roles_header=roles_header,
        claims_timestamp=claims_timestamp,
    )
    digest = hmac.new(
        signature_secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{TRUSTED_HEADER_SIGNATURE_VERSION}={digest}"


def verify_trusted_header_signature(
    *,
    tenant_id: str | None,
    subject_id: str,
    roles_header: str | None,
    claims_signature: str | None,
    claims_timestamp: str | None,
    signature_secret: str | None,
    signature_tolerance_seconds: int,
    current_time_seconds: int | None = None,
) -> None:
    if signature_secret is None or not signature_secret.strip():
        raise AuthenticationError("Auth claims signing secret is not configured.")
    if claims_signature is None or not claims_signature.strip():
        raise AuthenticationError("Auth claims signature header is required.")
    if claims_timestamp is None or not claims_timestamp.strip():
        raise AuthenticationError("Auth claims timestamp header is required.")
    if signature_tolerance_seconds <= 0:
        raise AuthenticationError("Auth claims signature tolerance must be greater than zero.")

    timestamp = _parse_claims_timestamp(claims_timestamp)
    now = int(time.time()) if current_time_seconds is None else current_time_seconds
    if abs(now - timestamp) > signature_tolerance_seconds:
        raise AuthenticationError("Auth claims signature timestamp is outside the allowed tolerance.")

    expected = sign_trusted_headers(
        tenant_id=tenant_id,
        subject_id=subject_id,
        roles_header=roles_header,
        claims_timestamp=claims_timestamp.strip(),
        signature_secret=signature_secret,
    )
    if not hmac.compare_digest(expected, claims_signature.strip()):
        raise AuthenticationError("Auth claims signature is invalid.")


def _canonical_claims_payload(
    *,
    tenant_id: str | None,
    subject_id: str,
    roles_header: str | None,
    claims_timestamp: str,
) -> str:
    roles = ",".join(sorted(_parse_roles(roles_header)))
    return "\n".join(
        [
            TRUSTED_HEADER_SIGNATURE_VERSION,
            tenant_id.strip() if tenant_id is not None else "",
            subject_id.strip(),
            roles,
            claims_timestamp.strip(),
        ]
    )


def _parse_roles(raw_roles: str | None) -> set[str]:
    if raw_roles is None:
        return set()
    return {role for role in ROLE_SPLIT_RE.split(raw_roles.strip()) if role}


def _parse_claims_timestamp(raw_timestamp: str | None) -> int:
    assert raw_timestamp is not None
    try:
        return int(raw_timestamp.strip())
    except ValueError as exc:
        raise AuthenticationError("Auth claims timestamp must be a Unix epoch integer.") from exc


def _has_text(value: str | None) -> bool:
    return value is not None and bool(value.strip())
