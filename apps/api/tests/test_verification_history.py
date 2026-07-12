from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.api import middleware, routes
from hallu_defense.domain.models import (
    AuditEvent,
    FinalDecision,
    VerificationRun,
    VerificationRunListRequest,
)
from hallu_defense.main import app
from hallu_defense.services.audit import (
    VERIFICATION_COMPLETED_EVENT,
    AuditLedger,
    AuditLedgerStorageError,
)
from hallu_defense.services.verification_history import (
    VerificationHistoryCursorError,
    VerificationHistoryIntegrityError,
    list_verification_history,
)


def test_verification_history_paginates_persisted_completion_events(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    for index, decision in enumerate(("allow", "repaired", "blocked"), start=1):
        ledger.append_completed_run(
            _verification_run(
                trace_id=f"tr_history_{index}",
                tenant_id="tenant-a",
                final_decision=FinalDecision(decision),
            ),
            path="/verification/run",
        )
    ledger.append_completed_run(
        _verification_run(
            trace_id="tr_other_tenant",
            tenant_id="tenant-b",
            final_decision=FinalDecision.ALLOW,
        ),
        path="/verification/run",
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
    reader = _StaticEventReader([_completion_event(metadata={})])

    with pytest.raises(VerificationHistoryIntegrityError, match="final_decision"):
        list_verification_history(
            reader,
            tenant_id="tenant-a",
            request=VerificationRunListRequest(),
        )


@pytest.mark.parametrize(
    ("path", "decision"),
    [
        ("/verification/run", FinalDecision.ALLOW),
        ("/v2/verification/run", FinalDecision.REPAIRED),
        ("/verification/replay", FinalDecision.REQUIRE_HUMAN_REVIEW),
    ],
)
def test_verification_history_accepts_every_completion_path(
    path: str,
    decision: FinalDecision,
) -> None:
    event = _completion_event(
        path=path,
        metadata={"final_decision": decision.value},
    )

    runs, cursor = list_verification_history(
        _StaticEventReader([event]),
        tenant_id="tenant-a",
        request=VerificationRunListRequest(trace_id=event.trace_id),
    )

    assert len(runs) == 1
    assert runs[0].trace_id == event.trace_id
    assert runs[0].final_decision is decision
    assert runs[0].created_at == event.created_at
    assert cursor is None


@pytest.mark.parametrize(
    ("update", "tenant_id", "trace_id", "message"),
    [
        ({"tenant_id": "tenant-b"}, "tenant-a", None, "requested tenant"),
        ({"trace_id": "tr_other_trace"}, "tenant-a", "tr_history_event", "requested trace"),
        ({"event_type": "http_request"}, "tenant-a", None, "event is invalid"),
        ({"method": "GET"}, "tenant-a", None, "event is invalid"),
        ({"path": "/verification/runs/list"}, "tenant-a", None, "event is invalid"),
        ({"status_code": 201}, "tenant-a", None, "event is invalid"),
        ({"outcome": "error"}, "tenant-a", None, "event is invalid"),
        ({"trace_id": "bad"}, "tenant-a", None, "event is invalid"),
        (
            {"metadata": {"final_decision": "allow", "unexpected": "not-allowed"}},
            "tenant-a",
            None,
            "event is invalid",
        ),
    ],
)
def test_verification_history_rejects_events_outside_the_requested_contract(
    update: dict[str, object],
    tenant_id: str,
    trace_id: str | None,
    message: str,
) -> None:
    event = _completion_event().model_copy(update=update)

    with pytest.raises(VerificationHistoryIntegrityError, match=message):
        list_verification_history(
            _StaticEventReader([event]),
            tenant_id=tenant_id,
            request=VerificationRunListRequest(trace_id=trace_id),
        )


@pytest.mark.parametrize(
    "update",
    [
        {"event_id": "invalid"},
        {"created_at": datetime(2026, 7, 11, 12, 0)},
        {"trace_id": "tr_" + "x" * 161},
    ],
)
def test_verification_history_rejects_invalid_event_id_or_timezone(
    update: dict[str, object],
) -> None:
    event = _completion_event().model_copy(update=update)

    with pytest.raises(VerificationHistoryIntegrityError, match="event is invalid"):
        list_verification_history(
            _StaticEventReader([event]),
            tenant_id="tenant-a",
            request=VerificationRunListRequest(),
        )


def test_verification_history_rejects_invalid_final_decision() -> None:
    event = _completion_event(metadata={"final_decision": "not-a-decision"})

    with pytest.raises(VerificationHistoryIntegrityError, match="invalid final_decision"):
        list_verification_history(
            _StaticEventReader([event]),
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
            "created_at": ledger.export_events(tenant_id="tenant-a", trace_id="tr_history_api")[0]
            .created_at.isoformat()
            .replace("+00:00", "Z"),
        }
    ]
    assert listed.json()["next_cursor"] is None
    assert other_tenant.status_code == 200
    assert other_tenant.json()["runs"] == []


@pytest.mark.parametrize(
    ("path", "extra_payload"),
    [
        ("/verification/run", {}),
        ("/v2/verification/run", {"schema_version": "2.0"}),
    ],
)
def test_verification_persistence_redaction_does_not_change_public_response(
    path: str,
    extra_payload: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    client = TestClient(app)
    message = "The password policy requires twelve characters."

    response = client.post(
        path,
        json={**extra_payload, "message_text": message},
        headers={"x-tenant-id": "tenant-response", "x-trace-id": "tr_response_safe"},
    )

    assert response.status_code == 200
    assert response.json()["input"]["message_text"] == message
    persisted = ledger.export(
        tenant_id="tenant-response",
        trace_id="tr_response_safe",
    )
    assert len(persisted) == 1
    assert persisted[0].input["message_text"] == "[REDACTED]"


@pytest.mark.parametrize(
    ("path", "extra_payload"),
    [
        ("/verification/run", {}),
        ("/v2/verification/run", {"schema_version": "2.0"}),
    ],
)
def test_verification_route_fails_closed_when_completion_persistence_fails(
    path: str,
    extra_payload: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()

    def fail_completion(_run: VerificationRun, *, path: str) -> None:
        del path
        raise AuditLedgerStorageError("database-password-must-not-leak")

    def fail_http_event(**_kwargs: object) -> None:
        raise AuditLedgerStorageError("database-password-must-not-leak")

    monkeypatch.setattr(ledger, "append_completed_run", fail_completion)
    monkeypatch.setattr(ledger, "append_event", fail_http_event)
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    monkeypatch.setattr(middleware, "audit_ledger", ledger)
    client = TestClient(app)

    response = client.post(
        path,
        json={**extra_payload, "message_text": "Persistence must succeed."},
        headers={"x-tenant-id": "tenant-fail", "x-trace-id": "tr_persist_fail"},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "Verification persistence is unavailable."
    assert "database-password-must-not-leak" not in response.text
    assert ledger.export() == []
    assert ledger.export_events() == []


@pytest.mark.parametrize(
    ("path", "extra_payload"),
    [
        ("/verification/run", {}),
        ("/v2/verification/run", {"schema_version": "2.0"}),
    ],
)
def test_verification_route_maps_real_jsonl_write_failure_to_generic_503(
    path: str,
    extra_payload: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_path = tmp_path / "blocked-audit-ledger.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    storage_path.mkdir()
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    monkeypatch.setattr(middleware, "audit_ledger", ledger)
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        path,
        json={**extra_payload, "message_text": "Persistence must be durable."},
        headers={"x-tenant-id": "tenant-jsonl-fail", "x-trace-id": "tr_jsonl_write_fail"},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "Verification persistence is unavailable."
    assert "blocked-audit-ledger" not in response.text
    assert ledger.export() == []
    assert ledger.export_events() == []


@pytest.mark.parametrize(
    ("path", "extra_payload"),
    [
        ("/verification/run", {}),
        ("/v2/verification/run", {"schema_version": "2.0"}),
    ],
)
def test_verification_route_retry_persists_one_canonical_completion_pair(
    path: str,
    extra_payload: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    client = TestClient(app)
    request = {**extra_payload, "message_text": "A stable idempotent response."}
    headers = {"x-tenant-id": "tenant-retry", "x-trace-id": "tr_route_retry"}

    first = client.post(path, json=request, headers=headers)
    retried = client.post(path, json=request, headers=headers)

    assert first.status_code == 200
    assert retried.status_code == 200
    assert retried.json()["created_at"] == first.json()["created_at"]
    assert len(ledger.export(tenant_id="tenant-retry", trace_id="tr_route_retry")) == 1
    completions = [
        event
        for event in ledger.export_events(
            tenant_id="tenant-retry",
            trace_id="tr_route_retry",
        )
        if event.event_type == VERIFICATION_COMPLETED_EVENT
    ]
    assert len(completions) == 1
    assert completions[0].path == path


def test_verification_route_retry_ignores_only_volatile_retrieval_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    client = TestClient(app)
    message = "Full-time employees receive 15 days of paid vacation per year."
    request = {
        "message_text": message,
        "task_type": "document_qa",
        "documents": [
            {
                "source_ref": "hr-manual-v7",
                "content": message,
                "authority": "internal",
            }
        ],
    }
    headers = {"x-tenant-id": "tenant-evidence", "x-trace-id": "tr_evidence_retry"}

    first = client.post("/verification/run", json=request, headers=headers)
    retried = client.post("/verification/run", json=request, headers=headers)

    assert first.status_code == 200
    assert retried.status_code == 200
    assert retried.json()["created_at"] == first.json()["created_at"]
    assert len(ledger.export(tenant_id="tenant-evidence", trace_id="tr_evidence_retry")) == 1


@pytest.mark.parametrize(
    "identity_update",
    [
        {"tenant_id": "tenant-other"},
        {"trace_id": "tr_orchestrator_other"},
    ],
)
def test_verification_route_rejects_orchestrator_identity_mismatch_before_persistence(
    identity_update: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = AuditLedger()
    unexpected = _verification_run(
        tenant_id="tenant-guard",
        trace_id="tr_identity_guard",
        final_decision=FinalDecision.ALLOW,
    ).model_copy(update=identity_update)
    monkeypatch.setattr(routes, "audit_ledger", ledger)
    monkeypatch.setattr(getattr(routes, "orchestrator"), "run", lambda _request: unexpected)
    client = TestClient(app)

    response = client.post(
        "/verification/run",
        json={"message_text": "The identity must stay bound."},
        headers={"x-tenant-id": "tenant-guard", "x-trace-id": "tr_identity_guard"},
    )

    assert response.status_code == 503
    assert response.json()["message"] == "Verification persistence is unavailable."
    assert ledger.export() == []
    assert ledger.export_events() == []


def test_verification_history_endpoint_maps_cursor_and_integrity_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _StaticEventReader([_completion_event(trace_id="tr_invalid_event_api", metadata={})])
    monkeypatch.setattr(routes, "audit_ledger", reader)
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


@pytest.mark.parametrize(
    "path",
    [
        "/verification/run",
        "/v2/verification/run",
        "/verification/replay",
        "/verification/runs/list",
    ],
)
def test_verification_persistence_endpoints_publish_503_contract(path: str) -> None:
    responses = app.openapi()["paths"][path]["post"]["responses"]

    assert "503" in responses
    assert responses["503"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ErrorResponse"
    )


class _StaticEventReader:
    def __init__(self, events: Sequence[AuditEvent]) -> None:
        self._events = list(events)

    def page_events(
        self,
        *,
        tenant_id: str,
        event_type: str,
        trace_id: str | None = None,
        before_created_at: datetime | None = None,
        before_event_id: str | None = None,
        limit: int,
    ) -> list[AuditEvent]:
        del tenant_id, event_type, trace_id, before_created_at, before_event_id
        return list(self._events[:limit])


def _completion_event(
    *,
    trace_id: str = "tr_history_event",
    tenant_id: str = "tenant-a",
    path: str = "/verification/run",
    metadata: dict[str, object] | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id="evt_history_event",
        trace_id=trace_id,
        tenant_id=tenant_id,
        event_type=VERIFICATION_COMPLETED_EVENT,
        method="POST",
        path=path,
        status_code=200,
        outcome="success",
        metadata=({"final_decision": FinalDecision.ALLOW.value} if metadata is None else metadata),
        created_at=datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc),
    )


def _verification_run(
    *,
    trace_id: str,
    tenant_id: str,
    final_decision: FinalDecision,
) -> VerificationRun:
    return VerificationRun(
        trace_id=trace_id,
        tenant_id=tenant_id,
        input={"message_text": "Verification history fixture."},
        claims=[],
        evidence=[],
        verdicts=[],
        final_decision=final_decision,
        final_text="Verification history fixture.",
        policy_version="test",
    )
