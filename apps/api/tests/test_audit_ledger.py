from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    AuditEvent,
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
    PostgresAuditLedgerStorage,
    create_audit_ledger,
)
from hallu_defense.services.postgres import RecordingSqlProvider


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


def test_jsonl_audit_ledger_redacts_nested_snapshot_fields(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=ledger_path)
    run = _verification_run().model_copy(
        update={
            "claims": [
                Claim(
                    claim_id="clm_secret",
                    text="This claim mentions password handling.",
                    canonical_form="canonical api_key value short",
                    metadata={"api_key": "short", "safe": "kept"},
                )
            ],
            "evidence": [
                Evidence(
                    evidence_id="ev_secret",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    content="This evidence mentions token handling.",
                    structured_content={"token": "short", "structure": {"secret": "short"}},
                )
            ],
            "verdicts": [
                ClaimVerdict(
                    claim_id="clm_secret",
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.9,
                    action=VerdictAction.ALLOW,
                    reason="The password evidence supports the claim.",
                    validator_trace={"secret": "short", "matched_rules": ["rule_ok"]},
                )
            ],
        }
    )

    ledger.append(run)

    stored = ledger.export(tenant_id="tenant-a", trace_id="tr_audit_run")[0]
    assert stored.claims[0].canonical_form == REDACTED
    assert stored.claims[0].metadata == {"api_key": REDACTED, "safe": "kept"}
    assert stored.evidence[0].structured_content == {
        "token": REDACTED,
        "structure": {"secret": REDACTED},
    }
    assert stored.verdicts[0].reason == REDACTED
    assert stored.verdicts[0].validator_trace == {
        "secret": REDACTED,
        "matched_rules": ["rule_ok"],
    }
    assert "short" not in ledger_path.read_text(encoding="utf-8")


def test_jsonl_audit_ledger_redacts_source_refs_and_bare_secret_values(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=ledger_path)
    bare_secret = "sk-" + "a" * 24
    run = _verification_run().model_copy(
        update={
            "input": {"message_text": f"Rotated value {bare_secret}."},
            "evidence": [
                Evidence(
                    evidence_id="ev_signed",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    source_ref="https://storage.example/hr.pdf?sig=abcdef1234567890",
                    content=f"Stored value {bare_secret} was present.",
                )
            ],
        }
    )

    ledger.append(run)

    raw_text = ledger_path.read_text(encoding="utf-8")
    stored = ledger.export(tenant_id="tenant-a", trace_id="tr_audit_run")[0]
    assert bare_secret not in raw_text
    assert "abcdef1234567890" not in raw_text
    assert stored.input["message_text"] == f"Rotated value {REDACTED}."
    assert stored.evidence[0].source_ref == f"https://storage.example/hr.pdf{REDACTED}"
    assert stored.evidence[0].content == f"Stored value {REDACTED} was present."


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


def test_postgres_audit_ledger_appends_run_with_exact_insert_and_redaction(
    tmp_path: Path,
) -> None:
    provider = RecordingSqlProvider()
    ledger = create_audit_ledger(_postgres_settings(tmp_path), sql_provider=provider)

    ledger.append(_verification_run())

    assert len(provider.calls) == 1
    method, statement, parameters = provider.calls[0]
    assert method == "execute"
    assert statement == (
        "INSERT INTO audit_runs (tenant_id, trace_id, payload, created_at) "
        "VALUES (%s, %s, %s::jsonb, %s)"
    )
    tenant_id, trace_id, payload_json, created_at = parameters
    assert tenant_id == "tenant-a"
    assert trace_id == "tr_audit_run"
    # Redaction is applied before the payload reaches the provider: the raw
    # secret never leaves the process and the marker is present (JSONL<->PG parity).
    assert isinstance(payload_json, str)
    assert "short" not in payload_json
    assert REDACTED in payload_json
    assert isinstance(created_at, datetime)


def test_postgres_audit_ledger_appends_event_with_exact_insert_and_redaction(
    tmp_path: Path,
) -> None:
    provider = RecordingSqlProvider()
    ledger = create_audit_ledger(_postgres_settings(tmp_path), sql_provider=provider)

    event = ledger.append_event(
        trace_id="tr_evt",
        tenant_id="tenant-a",
        event_type="http_request",
        method="POST",
        path="/tools/validate-output",
        status_code=200,
        outcome="success",
        metadata={"token": "short", "nested": {"password": "short"}},
    )

    assert event.metadata["token"] == REDACTED
    assert len(provider.calls) == 1
    method, statement, parameters = provider.calls[0]
    assert method == "execute"
    assert statement == (
        "INSERT INTO audit_events (tenant_id, trace_id, event_id, payload, created_at) "
        "VALUES (%s, %s, %s, %s::jsonb, %s)"
    )
    tenant_id, trace_id, event_id, payload_json, created_at = parameters
    assert tenant_id == "tenant-a"
    assert trace_id == "tr_evt"
    assert event_id == event.event_id
    assert isinstance(payload_json, str)
    assert "short" not in payload_json
    assert REDACTED in payload_json
    assert isinstance(created_at, datetime)


def test_postgres_audit_ledger_export_runs_uses_indexed_select_and_orders_chronologically(
    tmp_path: Path,
) -> None:
    newer_row = _run_payload_row("tr_newer")
    older_row = _run_payload_row("tr_older")
    provider = RecordingSqlProvider(fetch_all_rows=[newer_row, older_row])
    ledger = create_audit_ledger(_postgres_settings(tmp_path), sql_provider=provider)

    runs = ledger.export(tenant_id="tenant-a", trace_id="tr_filter")

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT payload FROM audit_runs WHERE tenant_id = %s AND trace_id = %s "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            ("tenant-a", "tr_filter", 1000),
        )
    ]
    # The DB returns newest-first (created_at DESC, id DESC tiebreaker); export
    # yields the most recent N in chronological (ascending) order for parity
    # with memory/jsonl.
    assert [run.trace_id for run in runs] == ["tr_older", "tr_newer"]


def test_postgres_audit_ledger_export_events_tenant_only_filters_on_tenant(
    tmp_path: Path,
) -> None:
    provider = RecordingSqlProvider(fetch_all_rows=[])
    ledger = create_audit_ledger(_postgres_settings(tmp_path), sql_provider=provider)

    ledger.export_events(tenant_id="tenant-a")

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT payload FROM audit_events WHERE tenant_id = %s "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            ("tenant-a", 1000),
        )
    ]


def test_postgres_audit_ledger_export_events_without_filters_uses_bare_select(
    tmp_path: Path,
) -> None:
    provider = RecordingSqlProvider(fetch_all_rows=[_event_payload_row("tr_evt")])
    ledger = create_audit_ledger(_postgres_settings(tmp_path), sql_provider=provider)

    events = ledger.export_events()

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT payload FROM audit_events ORDER BY created_at DESC, id DESC LIMIT %s",
            (1000,),
        )
    ]
    assert [event.trace_id for event in events] == ["tr_evt"]


def test_postgres_audit_ledger_export_limit_uses_configured_cap() -> None:
    provider = RecordingSqlProvider(fetch_all_rows=[])
    ledger = AuditLedger(
        storage=PostgresAuditLedgerStorage(connection=provider),
        export_max_records=5,
    )

    ledger.export(tenant_id="tenant-a")

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT payload FROM audit_runs WHERE tenant_id = %s "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            ("tenant-a", 5),
        )
    ]


def test_create_audit_ledger_postgres_requires_sql_provider(tmp_path: Path) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="SqlConnectionProvider"):
        create_audit_ledger(_postgres_settings(tmp_path))


def test_audit_ledger_rejects_storage_path_and_storage_together(tmp_path: Path) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="not both"):
        AuditLedger(
            storage_path=tmp_path / "ledger.jsonl",
            storage=PostgresAuditLedgerStorage(connection=RecordingSqlProvider()),
        )


def test_export_events_applies_newest_records_cap() -> None:
    ledger = AuditLedger(export_max_records=2)
    for index in range(3):
        ledger.append_event(
            trace_id=f"tr_{index}",
            tenant_id="tenant-a",
            event_type="http_request",
            method="GET",
            path="/health",
            status_code=200,
            outcome="success",
        )

    exported = ledger.export_events(tenant_id="tenant-a")

    # The cap keeps the most recent records; the oldest overflow is dropped.
    assert [event.trace_id for event in exported] == ["tr_1", "tr_2"]


def _postgres_settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="production",
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        audit_ledger_backend="postgres",
    )


def _run_payload_row(trace_id: str) -> dict[str, object]:
    run = _verification_run().model_copy(update={"trace_id": trace_id})
    row: dict[str, object] = {"payload": run.model_dump(mode="json")}
    return row


def _event_payload_row(trace_id: str) -> dict[str, object]:
    event = AuditEvent(
        event_id="evt_row",
        trace_id=trace_id,
        tenant_id="tenant-a",
        event_type="http_request",
        method="GET",
        path="/health",
        status_code=200,
        outcome="success",
    )
    row: dict[str, object] = {"payload": event.model_dump(mode="json")}
    return row


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
