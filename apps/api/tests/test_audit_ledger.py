from __future__ import annotations

import json
from pathlib import Path

import pytest

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    Claim,
    ClaimVerdict,
    Evidence,
    EvidenceKind,
    FinalDecision,
    VerdictAction,
    VerdictStatus,
    VerificationRun,
)
from hallu_defense.services.audit import (
    REDACTED,
    AuditLedger,
    AuditLedgerConfigurationError,
    AuditLedgerStorageError,
    create_audit_ledger,
)


def test_jsonl_audit_ledger_persists_and_reloads_events_by_tenant(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=ledger_path)

    ledger.append_event(
        trace_id="tr_audit_one",
        tenant_id="tenant-a",
        event_type="http_request",
        method="POST",
        path="/claims/extract",
        status_code=200,
        outcome="success",
        metadata={"duration_ms": 1.2},
    )
    ledger.append_event(
        trace_id="tr_audit_two",
        tenant_id="tenant-b",
        event_type="http_request",
        method="POST",
        path="/claims/extract",
        status_code=200,
        outcome="success",
    )

    reloaded = AuditLedger(storage_path=ledger_path)

    assert [event.trace_id for event in reloaded.export_events(tenant_id="tenant-a")] == [
        "tr_audit_one"
    ]
    assert [event.trace_id for event in reloaded.export_events(trace_id="tr_audit_two")] == [
        "tr_audit_two"
    ]


def test_jsonl_audit_ledger_persists_redacted_verification_runs(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=ledger_path)

    ledger.append(_verification_run())

    raw_text = ledger_path.read_text(encoding="utf-8")
    assert "short" not in raw_text
    assert REDACTED in raw_text

    reloaded = AuditLedger(storage_path=ledger_path)
    runs = reloaded.export(tenant_id="tenant-a", trace_id="tr_audit_run")

    assert len(runs) == 1
    run = runs[0]
    assert run.input["token"] == REDACTED
    assert run.claims[0].text == REDACTED
    assert run.evidence[0].content == REDACTED
    assert run.final_text == REDACTED


def test_jsonl_audit_ledger_redacts_event_metadata(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=ledger_path)

    event = ledger.append_event(
        trace_id="tr_audit_event_redaction",
        tenant_id="tenant-a",
        event_type="http_request",
        method="POST",
        path="/tools/validate-output",
        status_code=200,
        outcome="success",
        metadata={"token": "short", "nested": {"password": "short"}},
    )

    assert event.metadata["token"] == REDACTED
    assert event.metadata["nested"] == {"password": REDACTED}
    assert "short" not in ledger_path.read_text(encoding="utf-8")


def test_create_audit_ledger_rejects_memory_backend_in_production(tmp_path: Path) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="persistent"):
        create_audit_ledger(
            Settings(
                environment="production",
                policy_version="test",
                auth_required=True,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1000,
                audit_ledger_backend="memory",
            )
        )


def test_create_audit_ledger_accepts_jsonl_backend_in_production(tmp_path: Path) -> None:
    ledger = create_audit_ledger(
        Settings(
            environment="production",
            policy_version="test",
            auth_required=True,
            allowed_workspace=tmp_path,
            max_command_seconds=5,
            max_output_chars=1000,
            audit_ledger_backend="jsonl",
            audit_ledger_path=tmp_path / "audit-ledger.jsonl",
        )
    )

    ledger.append_event(
        trace_id="tr_jsonl_prod",
        tenant_id="tenant-a",
        event_type="http_request",
        method="GET",
        path="/health",
        status_code=200,
        outcome="success",
    )

    assert ledger.export_events(trace_id="tr_jsonl_prod")


def test_jsonl_audit_ledger_fails_closed_on_corrupt_record(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit-ledger.jsonl"
    ledger_path.write_text(json.dumps({"record_type": "unknown", "payload": {}}), encoding="utf-8")

    with pytest.raises(AuditLedgerStorageError, match="unsupported record_type"):
        AuditLedger(storage_path=ledger_path)


def _verification_run() -> VerificationRun:
    return VerificationRun(
        trace_id="tr_audit_run",
        tenant_id="tenant-a",
        input={"message_text": "safe", "token": "short"},
        claims=[
            Claim(
                claim_id="clm_secret",
                text="This claim mentions password handling.",
            )
        ],
        evidence=[
            Evidence(
                evidence_id="ev_secret",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                content="This evidence mentions token handling.",
            )
        ],
        verdicts=[
            ClaimVerdict(
                claim_id="clm_secret",
                status=VerdictStatus.SUPPORTED,
                confidence=0.9,
                action=VerdictAction.ALLOW,
                reason="Evidence supports the claim.",
            )
        ],
        final_decision=FinalDecision.ALLOW,
        final_text="The final text mentions secret handling.",
        policy_version="test",
    )
