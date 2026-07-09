from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from hallu_defense.api import dependencies
from hallu_defense.config import Settings
from hallu_defense.main import app
from hallu_defense.services.auth import (
    ANONYMOUS_SUBJECT,
    ADMIN_ROLE,
    APPROVAL_REVIEWER_ROLE,
    AUTH_CLAIMS_MODE_SIGNED_HEADERS,
    AUDITOR_ROLE,
    AuthenticationError,
    AuthorizationError,
    principal_from_headers,
    Principal,
    sign_trusted_headers,
)
from hallu_defense.services.secrets import SecretValue


class _FakeSecretManager:
    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert name == "auth/trusted-header-signing-key"
        assert field == "value"
        return SecretValue(name=name, _value="unit-signing-key")


def test_principal_defaults_to_anonymous_without_subject() -> None:
    principal = principal_from_headers(
        subject_id=None,
        roles_header="approval_reviewer",
        authorization=None,
        auth_required=False,
    )

    assert principal.subject_id == ANONYMOUS_SUBJECT
    assert principal.roles == frozenset()
    with pytest.raises(AuthorizationError):
        principal.require_role(APPROVAL_REVIEWER_ROLE)


def test_principal_parses_subject_and_roles() -> None:
    principal = principal_from_headers(
        subject_id="reviewer-1",
        roles_header="reader, approval_reviewer auditor",
        authorization="Bearer fixture",
        auth_required=True,
    )

    assert principal.subject_id == "reviewer-1"
    assert principal.has_role("reader")
    assert principal.has_role(APPROVAL_REVIEWER_ROLE)
    principal.require_role(APPROVAL_REVIEWER_ROLE)


def test_admin_role_satisfies_specific_role_requirements() -> None:
    principal = Principal(subject_id="admin-1", roles=frozenset({ADMIN_ROLE}))

    assert principal.has_role(APPROVAL_REVIEWER_ROLE)
    principal.require_role(APPROVAL_REVIEWER_ROLE)


def test_require_roles_rejects_missing_role_when_auth_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=True,
        allowed_workspace=Path("."),
        max_command_seconds=5,
        max_output_chars=1000,
    )
    monkeypatch.setattr(dependencies, "settings", settings)
    context = dependencies.RequestContext(
        tenant_id="tenant-a",
        trace_id="tr_rbac_missing",
        principal=Principal(subject_id="analyst", roles=frozenset({"verifier"})),
    )

    with pytest.raises(HTTPException) as exc_info:
        dependencies.require_roles(AUDITOR_ROLE)(context)

    assert exc_info.value.status_code == 403


def test_require_roles_allows_local_mode_without_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=False,
        allowed_workspace=Path("."),
        max_command_seconds=5,
        max_output_chars=1000,
    )
    monkeypatch.setattr(dependencies, "settings", settings)
    context = dependencies.RequestContext(
        tenant_id="tenant-a",
        trace_id="tr_rbac_local",
        principal=Principal(subject_id=ANONYMOUS_SUBJECT, roles=frozenset()),
    )

    assert dependencies.require_roles(AUDITOR_ROLE)(context) is context


def test_endpoint_role_matrix_covers_protected_routes() -> None:
    assert dependencies.ENDPOINT_ROLE_REQUIREMENTS == {
        "GET /metrics": frozenset({"metrics_reader"}),
        "POST /claims/extract": frozenset({"verifier"}),
        "POST /claims/classify": frozenset({"verifier"}),
        "POST /evidence/retrieve": frozenset({"verifier"}),
        "POST /documents/ingest": frozenset({"rag_writer"}),
        "POST /rag/corpus-grants/upsert": frozenset({"rag_writer"}),
        "POST /rag/corpus-grants/disable": frozenset({"rag_writer"}),
        "POST /rag/corpus-grants/list": frozenset({"rag_writer", "verifier"}),
        "POST /rag/corpus-grants/history": frozenset({"rag_writer", "verifier"}),
        "POST /rag/corpus-grants/history/diff": frozenset({"rag_writer", "verifier"}),
        "POST /claims/verify": frozenset({"verifier"}),
        "POST /response/repair": frozenset({"verifier"}),
        "POST /tools/validate-input": frozenset({"tool_operator"}),
        "POST /tools/validate-output": frozenset({"tool_operator"}),
        "POST /policy/evaluate": frozenset({"policy_evaluator"}),
        "POST /approvals/list": frozenset({"approval_reviewer"}),
        "POST /approvals/decide": frozenset({"approval_reviewer"}),
        "POST /repo/checks/run": frozenset({"sandbox_runner"}),
        "POST /audit/export": frozenset({"auditor"}),
        "POST /verification/run": frozenset({"verifier"}),
        "POST /verification/replay": frozenset({"verifier"}),
    }


def test_signed_headers_mode_accepts_valid_gateway_signature() -> None:
    signature = sign_trusted_headers(
        tenant_id="tenant-a",
        subject_id="reviewer-1",
        roles_header="reader, approval_reviewer",
        claims_timestamp="2000",
        signature_secret="unit-signing-key",
    )

    principal = principal_from_headers(
        tenant_id="tenant-a",
        subject_id="reviewer-1",
        roles_header="approval_reviewer reader",
        authorization="Bearer fixture",
        auth_required=True,
        claims_mode=AUTH_CLAIMS_MODE_SIGNED_HEADERS,
        claims_signature=signature,
        claims_timestamp="2000",
        signature_secret="unit-signing-key",
        signature_tolerance_seconds=300,
        current_time_seconds=2000,
    )

    assert principal.subject_id == "reviewer-1"
    assert principal.has_role(APPROVAL_REVIEWER_ROLE)


def test_signed_headers_mode_rejects_missing_signature() -> None:
    with pytest.raises(AuthenticationError, match="signature header"):
        principal_from_headers(
            tenant_id="tenant-a",
            subject_id="reviewer-1",
            roles_header="approval_reviewer",
            authorization="Bearer fixture",
            auth_required=True,
            claims_mode=AUTH_CLAIMS_MODE_SIGNED_HEADERS,
            claims_timestamp="2000",
            signature_secret="unit-signing-key",
            signature_tolerance_seconds=300,
            current_time_seconds=2000,
        )


def test_signed_headers_mode_rejects_tampered_claims() -> None:
    signature = sign_trusted_headers(
        tenant_id="tenant-a",
        subject_id="reviewer-1",
        roles_header="approval_reviewer",
        claims_timestamp="2000",
        signature_secret="unit-signing-key",
    )

    with pytest.raises(AuthenticationError, match="invalid"):
        principal_from_headers(
            tenant_id="tenant-b",
            subject_id="reviewer-1",
            roles_header="approval_reviewer",
            authorization="Bearer fixture",
            auth_required=True,
            claims_mode=AUTH_CLAIMS_MODE_SIGNED_HEADERS,
            claims_signature=signature,
            claims_timestamp="2000",
            signature_secret="unit-signing-key",
            signature_tolerance_seconds=300,
            current_time_seconds=2000,
        )


def test_signed_headers_mode_rejects_stale_timestamp() -> None:
    signature = sign_trusted_headers(
        tenant_id="tenant-a",
        subject_id="reviewer-1",
        roles_header="approval_reviewer",
        claims_timestamp="2000",
        signature_secret="unit-signing-key",
    )

    with pytest.raises(AuthenticationError, match="outside"):
        principal_from_headers(
            tenant_id="tenant-a",
            subject_id="reviewer-1",
            roles_header="approval_reviewer",
            authorization="Bearer fixture",
            auth_required=True,
            claims_mode=AUTH_CLAIMS_MODE_SIGNED_HEADERS,
            claims_signature=signature,
            claims_timestamp="2000",
            signature_secret="unit-signing-key",
            signature_tolerance_seconds=300,
            current_time_seconds=2401,
        )


def test_request_context_uses_signed_gateway_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=True,
        allowed_workspace=Path("."),
        max_command_seconds=5,
        max_output_chars=1000,
        auth_claims_mode=AUTH_CLAIMS_MODE_SIGNED_HEADERS,
        auth_claims_signature_secret_name="auth/trusted-header-signing-key",
        auth_claims_signature_tolerance_seconds=300,
    )
    monkeypatch.setattr(dependencies, "settings", settings)
    monkeypatch.setattr(dependencies, "secret_manager", _FakeSecretManager())
    timestamp = str(int(time.time()))
    signature = sign_trusted_headers(
        tenant_id="tenant-a",
        subject_id="reviewer-1",
        roles_header="approval_reviewer",
        claims_timestamp=timestamp,
        signature_secret="unit-signing-key",
    )

    context = dependencies.get_request_context(
        request=_request(),
        x_tenant_id="tenant-a",
        x_subject_id="reviewer-1",
        x_roles="approval_reviewer",
        x_auth_claims_signature=signature,
        x_auth_claims_timestamp=timestamp,
        authorization="Bearer fixture",
    )

    assert context.tenant_id == "tenant-a"
    assert context.principal.subject_id == "reviewer-1"
    assert context.principal.has_role(APPROVAL_REVIEWER_ROLE)


def _request() -> Request:
    return Request({"type": "http", "headers": []})


def test_audit_export_requires_auditor_role_when_auth_is_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=True,
        allowed_workspace=Path("."),
        max_command_seconds=5,
        max_output_chars=1000,
    )
    monkeypatch.setattr(dependencies, "settings", settings)
    client = TestClient(app)

    missing_role = client.post(
        "/audit/export",
        json={"include_events": True},
        headers={
            "Authorization": "Bearer fixture",
            "x-subject-id": "analyst",
            "x-roles": "verifier",
            "x-trace-id": "tr_audit_missing_role",
        },
    )
    allowed = client.post(
        "/audit/export",
        json={"include_events": True},
        headers={
            "Authorization": "Bearer fixture",
            "x-subject-id": "auditor-1",
            "x-roles": AUDITOR_ROLE,
            "x-trace-id": "tr_audit_role_allowed",
        },
    )

    assert missing_role.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["trace_id"] == "tr_audit_role_allowed"


def test_auth_required_requires_authorization_header() -> None:
    with pytest.raises(AuthenticationError, match="Authorization header"):
        principal_from_headers(
            subject_id="reviewer-1",
            roles_header="approval_reviewer",
            authorization=None,
            auth_required=True,
        )


def test_auth_required_requires_subject_header() -> None:
    with pytest.raises(AuthenticationError, match="subject header"):
        principal_from_headers(
            subject_id=None,
            roles_header="approval_reviewer",
            authorization="Bearer fixture",
            auth_required=True,
        )
