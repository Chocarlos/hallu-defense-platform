from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.api import dependencies
from hallu_defense.api import middleware as api_middleware
from hallu_defense.api.middleware import UNAUTHENTICATED_AUDIT_TENANT_ID
from hallu_defense.api import routes
from hallu_defense.config import AUTH_CLAIMS_MODE_OIDC_JWT, Settings
from hallu_defense.domain.models import (
    ApprovalListRequest,
    ToolCallEnvelope,
    ToolValidationResponse,
    VerdictAction,
)
from hallu_defense.main import app
from hallu_defense.services.approvals import ApprovalAuthorizationIssuer, ApprovalQueue
from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.content_security import ContentSecurityScanner
from hallu_defense.services.policy import PolicyEngine
from hallu_defense.services.tool_definitions import TrustedToolRegistry
from hallu_defense.services.tool_safety import ToolSafetyService
from test_oidc_jwt import _jwt, _write_jwks

DELETE_REPOSITORY_INPUT_SCHEMA = (
    TrustedToolRegistry.default().resolve("delete_repository").input_schema
)


def test_oidc_jwt_route_uses_token_tenant_for_response_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, ledger = _configure_oidc_route_test(tmp_path, monkeypatch)
    trace_id = "tr_oidc_route_tenant_audit"

    response = client.post(
        "/verification/run",
        json={"message_text": "Full-time employees receive 15 days of paid vacation per year."},
        headers=_oidc_headers(["verifier"], trace_id=trace_id),
    )

    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-a"
    events = ledger.export_events(trace_id=trace_id)
    assert len(events) == 1
    assert events[0].tenant_id == "tenant-a"


def test_oidc_jwt_route_roles_are_enforced_from_token_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ledger = _configure_oidc_route_test(tmp_path, monkeypatch)

    verifier_response = client.post(
        "/verification/run",
        json={"message_text": "The API returns a trace identifier."},
        headers=_oidc_headers(["verifier"], trace_id="tr_oidc_verifier_allowed"),
    )
    verifier_missing_auditor = client.post(
        "/audit/export",
        json={"include_events": True},
        headers=_oidc_headers(["verifier"], trace_id="tr_oidc_verifier_audit_forbidden"),
    )
    auditor_response = client.post(
        "/audit/export",
        json={"include_events": True},
        headers=_oidc_headers(["auditor"], trace_id="tr_oidc_auditor_allowed"),
    )
    auditor_missing_verifier = client.post(
        "/verification/run",
        json={"message_text": "The API returns a trace identifier."},
        headers=_oidc_headers(["auditor"], trace_id="tr_oidc_auditor_verify_forbidden"),
    )
    verifier_history = client.post(
        "/verification/runs/list",
        json={"limit": 5},
        headers=_oidc_headers(["verifier"], trace_id="tr_oidc_verifier_history"),
    )
    auditor_history = client.post(
        "/verification/runs/list",
        json={"limit": 5},
        headers=_oidc_headers(["auditor"], trace_id="tr_oidc_auditor_history"),
    )
    reviewer_history = client.post(
        "/verification/runs/list",
        json={"limit": 5},
        headers=_oidc_headers(
            ["approval_reviewer"],
            trace_id="tr_oidc_reviewer_history_forbidden",
        ),
    )

    assert verifier_response.status_code == 200
    assert verifier_missing_auditor.status_code == 403
    assert auditor_response.status_code == 200
    assert auditor_missing_verifier.status_code == 403
    assert verifier_history.status_code == 200
    assert auditor_history.status_code == 200
    assert reviewer_history.status_code == 403


def test_oidc_jwt_route_rejects_tenant_header_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, ledger = _configure_oidc_route_test(tmp_path, monkeypatch)
    trace_id = "tr_oidc_tenant_mismatch"

    response = client.post(
        "/verification/run",
        json={"message_text": "The API returns a trace identifier."},
        headers=_oidc_headers(
            ["verifier"],
            trace_id=trace_id,
            tenant_header="tenant-b",
        ),
    )

    assert response.status_code == 401
    assert "Tenant header does not match" in response.json()["message"]
    assert ledger.export_events(tenant_id="tenant-b") == []
    events = ledger.export_events(
        tenant_id=UNAUTHENTICATED_AUDIT_TENANT_ID,
        trace_id=trace_id,
    )
    assert len(events) == 1
    assert events[0].status_code == 401


def test_oidc_audit_body_tenant_mismatch_is_forbidden_before_ledger_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, middleware_ledger = _configure_oidc_route_test(tmp_path, monkeypatch)
    trace_id = "tr_oidc_audit_body_tenant_mismatch"

    class RecordingAuditReader:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def export(self, *, tenant_id: str, trace_id: str | None = None) -> list[object]:
            del trace_id
            self.calls.append(("runs", tenant_id))
            return []

        def export_events(
            self,
            *,
            tenant_id: str,
            trace_id: str | None = None,
        ) -> list[object]:
            del trace_id
            self.calls.append(("events", tenant_id))
            return []

    reader = RecordingAuditReader()
    monkeypatch.setattr(routes, "audit_ledger", reader)

    response = client.post(
        "/audit/export",
        json={"tenant_id": "tenant-b", "include_events": True},
        headers=_oidc_headers(["auditor"], trace_id=trace_id),
    )

    assert response.status_code == 403
    assert "does not match" in response.json()["message"]
    assert reader.calls == []
    assert middleware_ledger.export(tenant_id="tenant-b") == []
    assert middleware_ledger.export_events(tenant_id="tenant-b") == []
    events = middleware_ledger.export_events(tenant_id="tenant-a", trace_id=trace_id)
    assert len(events) == 1
    assert events[0].status_code == 403


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/verification/run",
            {"tenant_id": "tenant-b", "message_text": "Tenant isolation is mandatory."},
        ),
        (
            "/v2/verification/run",
            {
                "schema_version": "2.0",
                "tenant_id": "tenant-b",
                "message_text": "Tenant isolation is mandatory.",
            },
        ),
    ],
)
def test_oidc_verification_body_tenant_mismatch_is_forbidden_before_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    payload: dict[str, object],
) -> None:
    client, middleware_ledger = _configure_oidc_route_test(tmp_path, monkeypatch)
    trace_id = f"tr_oidc_body_tenant_{'v2' if path.startswith('/v2') else 'v1'}"

    class RecordingOrchestrator:
        def __init__(self) -> None:
            self.requests: list[object] = []

        def run(self, request: object) -> object:
            self.requests.append(request)
            raise AssertionError("orchestrator must not run for a tenant mismatch")

    orchestrator = RecordingOrchestrator()
    monkeypatch.setattr(routes, "orchestrator", orchestrator)

    response = client.post(
        path,
        json=payload,
        headers=_oidc_headers(["verifier"], trace_id=trace_id),
    )

    assert response.status_code == 403
    assert "does not match" in response.json()["message"]
    assert orchestrator.requests == []
    assert middleware_ledger.export(tenant_id="tenant-b") == []
    assert middleware_ledger.export_events(tenant_id="tenant-b") == []
    events = middleware_ledger.export_events(tenant_id="tenant-a", trace_id=trace_id)
    assert len(events) == 1
    assert events[0].status_code == 403


def test_oidc_tool_context_rejects_cross_tenant_before_safety_or_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, middleware_ledger = _configure_oidc_route_test(tmp_path, monkeypatch)
    queue = ApprovalQueue()

    class SafetyMustNotRun:
        def validate_input(self, _request: ToolCallEnvelope) -> object:
            raise AssertionError("tool safety must not process a tenant mismatch")

    monkeypatch.setattr(routes, "approval_queue", queue)
    monkeypatch.setattr(routes, "tool_safety", SafetyMustNotRun())
    trace_id = "tr_oidc_tool_tenant_mismatch"

    response = client.post(
        "/tools/validate-input",
        json={
            "tool_name": "delete_repository",
            "input": {"repo": "core"},
            "schema": DELETE_REPOSITORY_INPUT_SCHEMA,
            "risk_level": "high",
            "approval_required": True,
            "caller_context": {"tenant_id": "tenant-b", "subject": "spoofed"},
        },
        headers=_oidc_headers(["tool_operator"], trace_id=trace_id),
    )

    assert response.status_code == 403
    assert queue.list_for_tenant("tenant-a", ApprovalListRequest()) == []
    assert queue.list_for_tenant("tenant-b", ApprovalListRequest()) == []
    assert middleware_ledger.export_events(tenant_id="tenant-b") == []


def test_oidc_tool_output_rejects_cross_tenant_before_safety(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, middleware_ledger = _configure_oidc_route_test(tmp_path, monkeypatch)

    class SafetyMustNotRun:
        def validate_output(self, _request: ToolCallEnvelope) -> object:
            raise AssertionError("tool safety must not process a tenant mismatch")

    monkeypatch.setattr(routes, "tool_safety", SafetyMustNotRun())

    response = client.post(
        "/tools/validate-output",
        json={
            "tool_name": "fetch_config",
            "input": {"safe": "value"},
            "schema": {"type": "object"},
            "risk_level": "low",
            "approval_required": False,
            "caller_context": {"tenant_id": "tenant-b", "subject": "spoofed"},
        },
        headers=_oidc_headers(
            ["tool_operator"],
            trace_id="tr_oidc_tool_output_tenant_mismatch",
        ),
    )

    assert response.status_code == 403
    assert middleware_ledger.export_events(tenant_id="tenant-b") == []


def test_oidc_tool_output_service_receives_canonical_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _middleware_ledger = _configure_oidc_route_test(tmp_path, monkeypatch)

    class RecordingSafety:
        def __init__(self) -> None:
            self.requests: list[ToolCallEnvelope] = []

        def validate_output(
            self,
            request: ToolCallEnvelope,
            **_kwargs: object,
        ) -> ToolValidationResponse:
            self.requests.append(request)
            return ToolValidationResponse(
                allowed=True,
                action=VerdictAction.ALLOW,
                reason="Output is safe.",
            )

    safety = RecordingSafety()
    monkeypatch.setattr(routes, "tool_safety", safety)

    response = client.post(
        "/tools/validate-output",
        json={
            "tool_name": "fetch_config",
            "input": {"safe": "value"},
            "schema": {"type": "object"},
            "risk_level": "low",
            "approval_required": False,
            "caller_context": {
                "tenant_id": "tenant-a",
                "subject": "spoofed-output-subject",
            },
        },
        headers=_oidc_headers(
            ["tool_operator"],
            trace_id="tr_oidc_tool_output_canonical",
        ),
    )

    assert response.status_code == 200
    assert len(safety.requests) == 1
    assert safety.requests[0].caller_context["tenant_id"] == "tenant-a"
    assert safety.requests[0].caller_context["subject"] == "user-1"


def test_oidc_tool_requester_and_execution_fingerprint_use_canonical_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _middleware_ledger = _configure_oidc_route_test(tmp_path, monkeypatch)
    issuer = ApprovalAuthorizationIssuer()
    registry = TrustedToolRegistry.default()
    queue = ApprovalQueue(tool_registry=registry, authorization_issuer=issuer)
    safety = ToolSafetyService(
        policy_engine=PolicyEngine(
            Settings(
                environment="test",
                policy_version="oidc-tool-test",
                auth_required=False,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1_000,
            )
        ),
        content_scanner=ContentSecurityScanner(),
        tool_registry=registry,
        authorization_issuer=issuer,
    )

    class AllowAllRateLimiter:
        def allow(self, **_kwargs: object) -> bool:
            return True

    monkeypatch.setattr(routes, "approval_queue", queue)
    monkeypatch.setattr(routes, "tool_safety", safety)
    monkeypatch.setattr(routes, "tool_validation_rate_limiter", AllowAllRateLimiter())
    base_tool_call = {
        "tool_name": "delete_repository",
        "input": {"repo": "core"},
        "schema": DELETE_REPOSITORY_INPUT_SCHEMA,
        "risk_level": "high",
        "approval_required": True,
        "caller_context": {
            "tenant_id": "tenant-a",
            "subject": "spoofed-requester",
            "channel": "oidc-test",
        },
    }

    approval_response = client.post(
        "/tools/validate-input",
        json=base_tool_call,
        headers=_oidc_headers(["tool_operator"], trace_id="tr_oidc_tool_approval"),
    )

    assert approval_response.status_code == 200
    approval_id = approval_response.json()["approval_id"]
    approvals = queue.list_for_tenant("tenant-a", ApprovalListRequest())
    approval = next(item for item in approvals if item.approval_id == approval_id)
    assert approval.requested_by == "user-1"
    assert approval.tool_call.caller_context["subject"] == "user-1"
    assert approval.tool_call.caller_context["tenant_id"] == "tenant-a"

    decision_response = client.post(
        "/approvals/decide",
        json={"approval_id": approval_id, "decision": "approve"},
        headers=_oidc_headers(
            ["approval_reviewer"],
            trace_id="tr_oidc_tool_approval_decide",
        ),
    )
    assert decision_response.status_code == 200
    execution_token = decision_response.json()["execution_grant"]["execution_token"]
    execution_request = {
        **base_tool_call,
        "caller_context": {
            "tenant_id": "tenant-a",
            "subject": "different-spoof",
            "channel": "oidc-test",
        },
        "approval_id": approval_id,
        "approval_execution_token": execution_token,
    }

    execution_response = client.post(
        "/tools/validate-input",
        json=execution_request,
        headers=_oidc_headers(["tool_operator"], trace_id="tr_oidc_tool_execute"),
    )

    assert execution_response.status_code == 200
    assert execution_response.json()["allowed"] is True


def _configure_oidc_route_test(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[TestClient, AuditLedger]:
    settings = Settings(
        environment="local",
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        auth_claims_mode=AUTH_CLAIMS_MODE_OIDC_JWT,
        oidc_issuer="https://issuer.example",
        oidc_audience="hallu-defense-api",
        oidc_jwks_path=_write_jwks(tmp_path),
    )
    ledger = AuditLedger()
    monkeypatch.setattr(dependencies, "settings", settings)
    monkeypatch.setattr(dependencies, "_oidc_resolver", None)
    monkeypatch.setattr(dependencies, "_oidc_resolver_settings", None)
    monkeypatch.setattr(api_middleware, "audit_ledger", ledger)
    return TestClient(app), ledger


def _oidc_headers(
    roles: Iterable[str],
    *,
    trace_id: str,
    tenant_header: str | None = None,
) -> dict[str, str]:
    signed_jwt = _jwt(
        {
            "exp": 4102444800,
            "roles": list(roles),
        }
    )
    headers = {
        "Authorization": f"Bearer {signed_jwt}",
        "x-trace-id": trace_id,
    }
    if tenant_header is not None:
        headers["x-tenant-id"] = tenant_header
    return headers
