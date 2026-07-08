from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.api import dependencies
from hallu_defense.api import middleware as api_middleware
from hallu_defense.config import AUTH_CLAIMS_MODE_OIDC_JWT, Settings
from hallu_defense.main import app
from hallu_defense.services.audit import AuditLedger
from test_oidc_jwt import _jwt, _write_jwks


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

    assert verifier_response.status_code == 200
    assert verifier_missing_auditor.status_code == 403
    assert auditor_response.status_code == 200
    assert auditor_missing_verifier.status_code == 403


def test_oidc_jwt_route_rejects_tenant_header_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ledger = _configure_oidc_route_test(tmp_path, monkeypatch)

    response = client.post(
        "/verification/run",
        json={"message_text": "The API returns a trace identifier."},
        headers=_oidc_headers(
            ["verifier"],
            trace_id="tr_oidc_tenant_mismatch",
            tenant_header="tenant-b",
        ),
    )

    assert response.status_code == 401
    assert "Tenant header does not match" in response.json()["message"]


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
