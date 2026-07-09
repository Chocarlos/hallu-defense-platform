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

# Offline mirror of the Keycloak ``oidc_jwt`` protection contract: it uses the
# embedded unit signing keypair via ``oidc_jwks_path`` (no Keycloak, no network)
# so wrong-audience and expired tokens are rejected for the intended reason
# rather than on signature. The live wiring against a real Keycloak is exercised
# by scripts/dev/live_keycloak_oidc_smoke.py's ``--api`` mode.


def test_approval_reviewer_role_is_authorized_for_approvals_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ledger = _configure_keycloak_api_test(tmp_path, monkeypatch)

    response = client.post(
        "/approvals/list",
        json={},
        headers=_oidc_headers(["approval_reviewer"], trace_id="tr_keycloak_api_reviewer"),
    )

    assert response.status_code == 200


def test_wrong_role_is_forbidden_for_approvals_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ledger = _configure_keycloak_api_test(tmp_path, monkeypatch)

    response = client.post(
        "/approvals/list",
        json={},
        headers=_oidc_headers(["verifier"], trace_id="tr_keycloak_api_wrong_role"),
    )

    assert response.status_code == 403


def test_wrong_audience_token_is_rejected_with_401(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ledger = _configure_keycloak_api_test(tmp_path, monkeypatch)

    response = client.post(
        "/approvals/list",
        json={},
        headers=_oidc_headers(
            ["approval_reviewer"],
            trace_id="tr_keycloak_api_bad_aud",
            audience="wrong-audience",
        ),
    )

    assert response.status_code == 401


def test_expired_token_is_rejected_with_401(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ledger = _configure_keycloak_api_test(tmp_path, monkeypatch)

    response = client.post(
        "/approvals/list",
        json={},
        headers=_oidc_headers(
            ["approval_reviewer"],
            trace_id="tr_keycloak_api_expired",
            exp=1900,
        ),
    )

    assert response.status_code == 401


def test_token_tenant_claim_propagates_to_audit_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, ledger = _configure_keycloak_api_test(tmp_path, monkeypatch)
    trace_id = "tr_keycloak_api_tenant_audit"

    response = client.post(
        "/approvals/list",
        json={},
        headers=_oidc_headers(["approval_reviewer"], trace_id=trace_id),
    )

    assert response.status_code == 200
    events = ledger.export_events(trace_id=trace_id)
    assert len(events) == 1
    assert events[0].tenant_id == "tenant-a"


def _configure_keycloak_api_test(
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
    audience: str | None = None,
    exp: int = 4102444800,
    tenant_header: str | None = None,
) -> dict[str, str]:
    overrides: dict[str, object] = {"exp": exp, "roles": list(roles)}
    if audience is not None:
        overrides["aud"] = audience
    signed_jwt = _jwt(overrides)
    headers = {
        "Authorization": f"Bearer {signed_jwt}",
        "x-trace-id": trace_id,
    }
    if tenant_header is not None:
        headers["x-tenant-id"] = tenant_header
    return headers
