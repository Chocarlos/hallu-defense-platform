from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.api import routes
from hallu_defense.domain.models import VerificationRunListRequest
from hallu_defense.main import app
from hallu_defense.services.audit import AuditLedger
from hallu_defense.services.verification_history import (
    VERIFICATION_COMPLETED_EVENT,
    VerificationHistoryCursorError,
    VerificationHistoryIntegrityError,
    list_verification_history,
)


def test_verification_history_paginates_persisted_completion_events(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    for index, decision in enumerate(("allow", "repaired", "blocked"), start=1):
        ledger.append_event(
            trace_id=f"tr_history_{index}",
            tenant_id="tenant-a",
            event_type=VERIFICATION_COMPLETED_EVENT,
            method="POST",
            path="/verification/run",
            status_code=200,
            outcome="success",
            metadata={"final_decision": decision},
        )
    ledger.append_event(
        trace_id="tr_other_tenant",
        tenant_id="tenant-b",
        event_type=VERIFICATION_COMPLETED_EVENT,
        method="POST",
        path="/verification/run",
        status_code=200,
        outcome="success",
        metadata={"final_decision": "allow"},
    )
    # More noise than the legacy export cap must not hide older completion events.
    for index in range(1_005):
        ledger.append_event(
            trace_id=f"tr_noise_{index}",
            tenant_id="tenant-a",
            event_type="http_request",
            method="GET",
            path="/health",
            status_code=200,
            outcome="success",
        )

    reloaded = AuditLedger(storage_path=storage_path)
    first, cursor = list_verification_history(
        reloaded,
        tenant_id="tenant-a",
        request=VerificationRunListRequest(limit=2),
    )
    assert len(first) == 2
    assert cursor is not None

    second, final_cursor = list_verification_history(
        reloaded,
        tenant_id="tenant-a",
        request=VerificationRunListRequest(limit=2, cursor=cursor),
    )
    assert len(second) == 1
    assert final_cursor is None
    assert {item.trace_id for item in [*first, *second]} == {
        "tr_history_1",
        "tr_history_2",
        "tr_history_3",
    }
    assert len({(item.trace_id, item.created_at) for item in [*first, *second]}) == 3


def test_verification_history_rejects_malformed_cursor() -> None:
    with pytest.raises(VerificationHistoryCursorError, match="cursor is invalid"):
        list_verification_history(
            AuditLedger(),
            tenant_id="tenant-a",
            request=VerificationRunListRequest(cursor="not+a+cursor"),
        )


def test_verification_history_fails_closed_on_invalid_completion_event() -> None:
    ledger = AuditLedger()
    ledger.append_event(
        trace_id="tr_invalid_history",
        tenant_id="tenant-a",
        event_type=VERIFICATION_COMPLETED_EVENT,
        method="POST",
        path="/verification/run",
        status_code=200,
        outcome="success",
        metadata={},
    )

    with pytest.raises(VerificationHistoryIntegrityError, match="final_decision"):
        list_verification_history(
            ledger,
            tenant_id="tenant-a",
            request=VerificationRunListRequest(),
        )


def test_verification_route_records_safe_history_and_list_is_tenant_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    client = TestClient(app)

    created = client.post(
        "/verification/run",
        json={"message_text": "The API returns a trace identifier."},
        headers={"x-tenant-id": "tenant-a", "x-trace-id": "tr_history_api"},
    )
    listed = client.post(
        "/verification/runs/list",
        json={"limit": 10},
        headers={"x-tenant-id": "tenant-a", "x-trace-id": "tr_history_list"},
    )
    other_tenant = client.post(
        "/verification/runs/list",
        json={"limit": 10},
        headers={"x-tenant-id": "tenant-b", "x-trace-id": "tr_history_other"},
    )

    assert created.status_code == 200
    assert listed.status_code == 200
    assert listed.json()["runs"] == [
        {
            "trace_id": "tr_history_api",
            "final_decision": created.json()["final_decision"],
            "created_at": ledger.export_events(
                tenant_id="tenant-a", trace_id="tr_history_api"
            )[0].created_at.isoformat().replace("+00:00", "Z"),
        }
    ]
    assert listed.json()["next_cursor"] is None
    assert other_tenant.status_code == 200
    assert other_tenant.json()["runs"] == []


def test_verification_history_endpoint_maps_cursor_and_integrity_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()
    ledger.append_event(
        trace_id="tr_invalid_event_api",
        tenant_id="tenant-a",
        event_type=VERIFICATION_COMPLETED_EVENT,
        method="POST",
        path="/verification/run",
        status_code=200,
        outcome="success",
        metadata={},
    )
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    client = TestClient(app)

    invalid_cursor = client.post(
        "/verification/runs/list",
        json={"cursor": "not+a+cursor"},
        headers={"x-tenant-id": "tenant-a"},
    )
    corrupt_history = client.post(
        "/verification/runs/list",
        json={},
        headers={"x-tenant-id": "tenant-a"},
    )

    assert invalid_cursor.status_code == 400
    assert invalid_cursor.json()["message"] == "Verification history cursor is invalid."
    assert corrupt_history.status_code == 503
    assert corrupt_history.json()["message"] == "Verification history is unavailable."
