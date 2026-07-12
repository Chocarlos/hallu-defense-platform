from __future__ import annotations

import json
import math
import threading
import traceback
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import hallu_defense.services.audit as audit_service
from hallu_defense.api import routes
from hallu_defense.api.dependencies import RequestContext
from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    AuditEvent,
    AuditExportRequest,
    Authority,
    Claim,
    ClaimVerdict,
    Evidence,
    EvidenceKind,
    FinalDecision,
    Freshness,
    SourceSpan,
    StalenessClass,
    VerdictAction,
    VerdictStatus,
    VerificationRun,
)
from hallu_defense.main import app
from hallu_defense.services.audit import (
    AUDIT_REQUEST_COMMITMENT_STORAGE_KEY,
    REDACTED,
    AuditLedger,
    AuditLedgerConfigurationError,
    AuditLedgerError,
    AuditLedgerSnapshot,
    AuditLedgerStorageError,
    CompletedVerificationRecord,
    PostgresAuditLedgerStorage,
    ReplaySourceConflictError,
    create_audit_ledger,
)
from hallu_defense.services.auth import AUDITOR_ROLE, Principal
from hallu_defense.services.postgres import RecordingSqlProvider
from hallu_defense.services.secrets import SecretValue

TEST_RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _AuditCommitmentSecretManager:
    def __init__(self, value: str = "a" * 48) -> None:
        self._value = value

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        assert name == "audit/request-commitment-key"
        assert field == "value"
        return SecretValue(name=name, _value=self._value)


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
    assert run.claims[0].text == "This claim mentions password handling."
    assert run.evidence[0].content == "This evidence mentions token handling."
    assert run.final_text == "The final text mentions secret handling."


def test_jsonl_audit_ledger_redacts_nested_snapshot_fields(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=ledger_path)
    bare_secret = "sk-" + "b" * 24
    run = _verification_run().model_copy(
        update={
            "claims": [
                Claim(
                    claim_id="clm_secret",
                    text="This claim mentions password handling.",
                    canonical_form=f"canonical credential {bare_secret}",
                    metadata={"api_key": "short", "safe": "kept"},
                )
            ],
            "evidence": [
                Evidence(
                    evidence_id="ev_secret",
                    kind=EvidenceKind.DOCUMENT_CHUNK,
                    source_ref="audit-source",
                    content="This evidence mentions token handling.",
                    structured_content={"token": "short", "structure": {"secret": "short"}},
                    authority=Authority.UNKNOWN,
                    freshness=Freshness(
                        retrieved_at=TEST_RETRIEVED_AT,
                        staleness_class=StalenessClass.UNKNOWN,
                    ),
                )
            ],
            "verdicts": [
                ClaimVerdict(
                    claim_id="clm_secret",
                    status=VerdictStatus.SUPPORTED,
                    confidence=0.9,
                    action=VerdictAction.ALLOW,
                    reason=f"The leaked credential {bare_secret} supports the claim.",
                    validator_trace={"secret": "short", "matched_rules": ["rule_ok"]},
                )
            ],
        }
    )

    ledger.append(run)

    stored = ledger.export(tenant_id="tenant-a", trace_id="tr_audit_run")[0]
    assert stored.claims[0].canonical_form == f"canonical credential {REDACTED}"
    assert stored.claims[0].metadata == {"api_key": REDACTED, "safe": "kept"}
    assert stored.evidence[0].structured_content == {
        "token": REDACTED,
        "structure": {"secret": REDACTED},
    }
    assert stored.verdicts[0].reason == (
        f"The leaked credential {REDACTED} supports the claim."
    )
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
                    structured_content={},
                    authority=Authority.UNKNOWN,
                    freshness=Freshness(
                        retrieved_at=TEST_RETRIEVED_AT,
                        staleness_class=StalenessClass.UNKNOWN,
                    ),
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
    assert stored.evidence[0].source_ref == (
        f"https://storage.example/hr.pdf?sig={REDACTED}"
    )
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


def test_create_audit_ledger_requires_vault_commitment_secret_in_production(
    tmp_path: Path,
) -> None:
    settings = Settings(
        environment="production",
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        audit_ledger_backend="postgres",
    )

    with pytest.raises(AuditLedgerConfigurationError, match="commitment secret name"):
        create_audit_ledger(settings, sql_provider=RecordingSqlProvider())


def test_create_audit_ledger_resolves_production_commitment_through_vault(
    tmp_path: Path,
) -> None:
    settings = _postgres_settings(tmp_path)
    manager = _AuditCommitmentSecretManager()

    ledger = create_audit_ledger(
        settings,
        sql_provider=RecordingSqlProvider(),
        secret_manager=manager,
    )

    assert ledger._request_commitment_key == b"a" * 48


def test_create_audit_ledger_rejects_short_vault_commitment_key(tmp_path: Path) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="at least 32 bytes"):
        create_audit_ledger(
            _postgres_settings(tmp_path),
            sql_provider=RecordingSqlProvider(),
            secret_manager=_AuditCommitmentSecretManager("too-short"),
        )


@pytest.mark.parametrize("environment", ["production", "staging", " production "])
def test_create_audit_ledger_rejects_jsonl_in_production_like_environments(
    tmp_path: Path,
    environment: str,
) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="PostgreSQL"):
        create_audit_ledger(
            Settings(
                environment=environment,
                policy_version="test",
                auth_required=True,
                allowed_workspace=tmp_path,
                max_command_seconds=5,
                max_output_chars=1000,
                audit_ledger_backend="jsonl",
                audit_ledger_path=tmp_path / "audit-ledger.jsonl",
            )
        )


def test_jsonl_audit_ledger_fails_closed_on_corrupt_record(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit-ledger.jsonl"
    ledger_path.write_text(json.dumps({"record_type": "unknown", "payload": {}}), encoding="utf-8")

    with pytest.raises(AuditLedgerStorageError, match="unsupported record_type"):
        AuditLedger(storage_path=ledger_path)


def test_postgres_audit_ledger_appends_run_with_exact_insert_and_redaction(
    tmp_path: Path,
) -> None:
    provider = RecordingSqlProvider()
    ledger = create_audit_ledger(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=_AuditCommitmentSecretManager(),
    )

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
    ledger = create_audit_ledger(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=_AuditCommitmentSecretManager(),
    )

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
    older_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    newer_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    newer_row = _run_payload_row("tr_newer", row_id=2, created_at=newer_at)
    older_row = _run_payload_row("tr_older", row_id=1, created_at=older_at)
    provider = RecordingSqlProvider(fetch_all_rows=[newer_row, older_row])
    ledger = create_audit_ledger(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=_AuditCommitmentSecretManager(),
    )

    runs = ledger.export(tenant_id="tenant-a")

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
            "FROM audit_runs "
            "WHERE tenant_id = %s "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            ("tenant-a", 1000),
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
    ledger = create_audit_ledger(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=_AuditCommitmentSecretManager(),
    )

    ledger.export_events(tenant_id="tenant-a")

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT id, tenant_id, trace_id, event_id, created_at, payload "
            "FROM audit_events WHERE tenant_id = %s "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            ("tenant-a", 1000),
        )
    ]


def test_postgres_audit_ledger_export_events_without_filters_uses_bare_select(
    tmp_path: Path,
) -> None:
    provider = RecordingSqlProvider(fetch_all_rows=[_event_payload_row("tr_evt")])
    ledger = create_audit_ledger(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=_AuditCommitmentSecretManager(),
    )

    events = ledger.export_events()

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT id, tenant_id, trace_id, event_id, created_at, payload "
            "FROM audit_events ORDER BY created_at DESC, id DESC LIMIT %s",
            (1000,),
        )
    ]
    assert [event.trace_id for event in events] == ["tr_evt"]


def test_postgres_audit_event_page_filters_type_and_uses_keyset_before_limit(
    tmp_path: Path,
) -> None:
    cursor_time = datetime(2027, 7, 10, 12, 0, tzinfo=timezone.utc)
    provider = RecordingSqlProvider(
        fetch_all_rows=[_event_payload_row("tr_completed", event_type="verification_completed")]
    )
    ledger = create_audit_ledger(
        _postgres_settings(tmp_path),
        sql_provider=provider,
        secret_manager=_AuditCommitmentSecretManager(),
    )

    events = ledger.page_events(
        tenant_id="tenant-a",
        event_type="verification_completed",
        trace_id="tr_completed",
        before_created_at=cursor_time,
        before_event_id="evt_cursor",
        limit=21,
    )

    assert provider.calls == [
        (
            "fetch_all",
            "SELECT id, tenant_id, trace_id, event_id, created_at, payload "
            "FROM audit_events WHERE tenant_id = %s "
            "AND payload ->> 'event_type' = %s AND trace_id = %s "
            "AND (created_at, event_id) < (%s, %s) "
            "ORDER BY created_at DESC, event_id DESC LIMIT %s",
            (
                "tenant-a",
                "verification_completed",
                "tr_completed",
                cursor_time,
                "evt_cursor",
                21,
            ),
        )
    ]
    assert [event.trace_id for event in events] == ["tr_completed"]


def test_postgres_audit_event_page_rejects_duplicate_database_row_id() -> None:
    row = _event_payload_row("tr_duplicate_page", event_type="verification_completed")
    provider = RecordingSqlProvider(fetch_all_rows=[row, dict(row)])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="duplicate database row ID"):
        ledger.page_events(
            tenant_id="tenant-a",
            event_type="verification_completed",
            trace_id="tr_duplicate_page",
            limit=2,
        )


def test_postgres_audit_event_page_rejects_duplicate_event_id_across_timestamps() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _event_payload_row(
                "tr_duplicate_page_event",
                event_type="verification_completed",
                row_id=2,
                event_id="evt_duplicate_page_identity",
                created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            _event_payload_row(
                "tr_duplicate_page_event",
                event_type="verification_completed",
                row_id=1,
                event_id="evt_duplicate_page_identity",
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="duplicate tenant event ID"):
        ledger.page_events(
            tenant_id="tenant-a",
            event_type="verification_completed",
            trace_id="tr_duplicate_page_event",
            limit=2,
        )


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
            "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
            "FROM audit_runs "
            "WHERE tenant_id = %s "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            ("tenant-a", 5),
        )
    ]


def test_postgres_replay_source_filters_before_two_row_cardinality_limit() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _run_payload_row(
                "tr_replay_source_lookup",
                completion_path="/verification/run",
            )
        ]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    source = ledger.find_replay_source(
        tenant_id="tenant-a",
        trace_id="tr_replay_source_lookup",
    )

    assert source is not None
    assert source.trace_id == "tr_replay_source_lookup"
    assert provider.calls == [
        (
            "fetch_all",
            "SELECT id, tenant_id, trace_id, completion_path, created_at, payload "
            "FROM audit_runs WHERE tenant_id = %s AND trace_id = %s "
            "AND payload #>> '{input,replay_of}' IS NULL "
            "ORDER BY created_at DESC, id DESC LIMIT 2",
            ("tenant-a", "tr_replay_source_lookup"),
        )
    ]


def test_postgres_replay_source_rejects_two_exact_original_candidates() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _run_payload_row(
                "tr_replay_source_ambiguous",
                row_id=2,
                created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                completion_path="/v2/verification/run",
            ),
            _run_payload_row(
                "tr_replay_source_ambiguous",
                row_id=1,
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                completion_path="/verification/run",
            ),
        ]
    )
    ledger = AuditLedger(
        storage=PostgresAuditLedgerStorage(connection=provider),
        export_max_records=1,
    )

    with pytest.raises(ReplaySourceConflictError, match="multiple original runs"):
        ledger.find_replay_source(
            tenant_id="tenant-a",
            trace_id="tr_replay_source_ambiguous",
        )

    assert provider.calls[0][1].endswith("ORDER BY created_at DESC, id DESC LIMIT 2")


@pytest.mark.parametrize("replay_marker", ["tr_replay_source_original", 7])
def test_postgres_replay_source_rejects_provider_replay_row(
    replay_marker: object,
) -> None:
    row = _run_payload_row(
        "tr_replay_source_wrong_row",
        completion_path="/verification/run",
    )
    payload = row["payload"]
    assert isinstance(payload, dict)
    payload["input"] = {"replay_of": replay_marker}
    provider = RecordingSqlProvider(fetch_all_rows=[row])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="returned a replayed verification run"):
        ledger.find_replay_source(
            tenant_id="tenant-a",
            trace_id="tr_replay_source_wrong_row",
        )


@pytest.mark.parametrize("backend", ["memory", "jsonl"])
def test_local_replay_source_excludes_any_non_null_replay_marker(
    tmp_path: Path,
    backend: str,
) -> None:
    ledger_path = tmp_path / "replay-marker.jsonl" if backend == "jsonl" else None
    ledger = AuditLedger(storage_path=ledger_path)
    run = _verification_run().model_copy(
        update={
            "trace_id": "tr_replay_source_non_null_marker",
            "input": {"replay_of": 7},
        },
        deep=True,
    )
    ledger.append(run)

    assert (
        ledger.find_replay_source(
            tenant_id="tenant-a",
            trace_id="tr_replay_source_non_null_marker",
        )
        is None
    )
    if ledger_path is not None:
        assert (
            AuditLedger(storage_path=ledger_path).find_replay_source(
                tenant_id="tenant-a",
                trace_id="tr_replay_source_non_null_marker",
            )
            is None
        )


def test_audit_export_route_uses_one_snapshot_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SnapshotOnlyReader:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str | None, bool]] = []

        def export_snapshot(
            self,
            *,
            tenant_id: str,
            trace_id: str | None,
            include_events: bool,
        ) -> AuditLedgerSnapshot:
            self.calls.append((tenant_id, trace_id, include_events))
            return AuditLedgerSnapshot(runs=(), events=())

        def export(self, **_kwargs: object) -> list[object]:
            raise AssertionError("The route must not perform an independent run read")

        def export_events(self, **_kwargs: object) -> list[object]:
            raise AssertionError("The route must not perform an independent event read")

    reader = SnapshotOnlyReader()
    monkeypatch.setattr(routes, "audit_ledger", reader)

    response = routes.export_audit(
        request=AuditExportRequest(
            tenant_id="tenant-a",
            trace_id="tr_snapshot_route",
            include_events=True,
        ),
        context=RequestContext(
            tenant_id="tenant-a",
            trace_id="tr_snapshot_request",
            principal=Principal(
                subject_id="auditor-a",
                roles=frozenset({AUDITOR_ROLE}),
            ),
        ),
    )

    assert response.trace_id == "tr_snapshot_request"
    assert response.runs == []
    assert response.events == []
    assert reader.calls == [("tenant-a", "tr_snapshot_route", True)]


def test_audit_export_snapshot_failure_returns_safe_documented_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingSnapshotReader:
        def export_snapshot(self, **_kwargs: object) -> AuditLedgerSnapshot:
            raise AuditLedgerStorageError("database-password-must-not-leak")

    monkeypatch.setattr(routes, "audit_ledger", FailingSnapshotReader())

    response = TestClient(app).post(
        "/audit/export",
        json={"include_events": True},
        headers={
            "x-tenant-id": "tenant-a",
            "x-trace-id": "tr_audit_export_failure",
        },
    )

    assert response.status_code == 503
    assert response.json()["message"] == routes.AUDIT_HISTORY_UNAVAILABLE_MESSAGE
    assert "database-password-must-not-leak" not in response.text
    responses = app.openapi()["paths"]["/audit/export"]["post"]["responses"]
    assert responses["503"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/ErrorResponse"
    )


def test_postgres_export_snapshot_excludes_commit_between_former_reads() -> None:
    former_provider = _InterleavingSnapshotProvider()
    former_storage = PostgresAuditLedgerStorage(connection=former_provider)

    former_runs = former_storage.load_runs(
        tenant_id="tenant-a",
        trace_id=None,
        limit=10,
    )
    former_events = former_storage.load_events(
        tenant_id="tenant-a",
        trace_id=None,
        limit=10,
    )

    assert [run.trace_id for run in former_runs] == ["tr_snapshot_initial"]
    assert [event.trace_id for event in former_events] == [
        "tr_snapshot_initial",
        "tr_snapshot_concurrent",
    ]
    assert former_provider.external_commit_count == 1

    provider = _InterleavingSnapshotProvider()
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    snapshot = ledger.export_snapshot(tenant_id="tenant-a")

    assert [run.trace_id for run in snapshot.runs] == ["tr_snapshot_initial"]
    assert [event.trace_id for event in snapshot.events] == ["tr_snapshot_initial"]
    assert provider.external_commit_count == 1
    assert provider.transaction_count == 1
    assert provider.base_fetch_count == 0
    assert [call[0] for call in provider.calls] == [
        "transaction_enter",
        "transaction_execute",
        "transaction_fetch_all",
        "external_commit",
        "transaction_fetch_all",
        "transaction_exit",
    ]
    assert provider.calls[1][1] == ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    snapshot_fetches = [call for call in provider.calls if call[0] == "transaction_fetch_all"]
    assert [call[2] for call in snapshot_fetches] == [
        ("tenant-a", 1001),
        ("tenant-a", 1001),
    ]


def test_postgres_export_snapshot_without_events_skips_event_select() -> None:
    provider = _InterleavingSnapshotProvider()
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    snapshot = ledger.export_snapshot(tenant_id="tenant-a", include_events=False)

    assert [run.trace_id for run in snapshot.runs] == ["tr_snapshot_initial"]
    assert snapshot.events == ()
    transaction_selects = [
        statement
        for method, statement, _parameters in provider.calls
        if method == "transaction_fetch_all"
    ]
    assert len(transaction_selects) == 1
    assert "FROM audit_runs" in transaction_selects[0]


def test_postgres_export_snapshot_uses_lookahead_but_returns_configured_cap() -> None:
    older_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    newer_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    newer_run = _run_payload_row(
        "tr_snapshot_capped_newer",
        row_id=2,
        created_at=newer_at,
        completion_path="/v2/verification/run",
    )
    older_run = _run_payload_row(
        "tr_snapshot_capped_older",
        row_id=1,
        created_at=older_at,
        completion_path="/verification/run",
    )
    newer_event = _event_payload_row(
        "tr_snapshot_capped_newer",
        event_type="verification_completed",
        row_id=2,
        event_id="evt_snapshot_capped_newer",
        created_at=newer_at,
    )
    newer_event_payload = newer_event["payload"]
    assert isinstance(newer_event_payload, dict)
    newer_event_payload["path"] = "/v2/verification/run"
    older_event = _event_payload_row(
        "tr_snapshot_capped_older",
        event_type="verification_completed",
        row_id=1,
        event_id="evt_snapshot_capped_older",
        created_at=older_at,
    )
    provider = _StaticSnapshotProvider(
        run_rows=[newer_run, older_run],
        event_rows=[newer_event, older_event],
    )
    ledger = AuditLedger(
        storage=PostgresAuditLedgerStorage(connection=provider),
        export_max_records=1,
    )

    snapshot = ledger.export_snapshot(tenant_id="tenant-a")

    assert [run.trace_id for run in snapshot.runs] == ["tr_snapshot_capped_newer"]
    assert [event.trace_id for event in snapshot.events] == ["tr_snapshot_capped_newer"]


def test_postgres_export_snapshot_rejects_run_completion_decision_drift() -> None:
    provider = _InterleavingSnapshotProvider(initial_event_decision="blocked")
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="mismatched run/completion decisions"):
        ledger.export_snapshot(tenant_id="tenant-a")


@pytest.mark.parametrize("export_max_records", [1, 1000])
def test_postgres_export_snapshot_rejects_cross_path_completion_drift(
    export_max_records: int,
) -> None:
    run_row = _run_payload_row(
        "tr_snapshot_path_drift",
        completion_path="/verification/run",
    )
    event_row = _event_payload_row(
        "tr_snapshot_path_drift",
        event_type="verification_completed",
        event_id="evt_snapshot_path_drift",
    )
    event_payload = event_row["payload"]
    assert isinstance(event_payload, dict)
    event_payload["path"] = "/v2/verification/run"
    provider = _StaticSnapshotProvider(
        run_rows=[run_row],
        event_rows=[event_row],
    )
    ledger = AuditLedger(
        storage=PostgresAuditLedgerStorage(connection=provider),
        export_max_records=export_max_records,
    )

    with pytest.raises(AuditLedgerStorageError, match="mismatched completion paths"):
        ledger.export_snapshot(tenant_id="tenant-a")


def test_postgres_export_snapshot_rejects_replay_provenance_drift() -> None:
    run_row = _run_payload_row(
        "tr_snapshot_replay_drift",
        completion_path="/verification/replay",
    )
    run_payload = run_row["payload"]
    assert isinstance(run_payload, dict)
    run_payload["input"] = {"replay_of": "tr_snapshot_replay_source"}
    completion = _event_payload_row(
        "tr_snapshot_replay_drift",
        event_type="verification_completed",
        row_id=1,
        event_id="evt_snapshot_replay_completion",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        final_decision="allow",
    )
    completion_payload = completion["payload"]
    assert isinstance(completion_payload, dict)
    completion_payload["path"] = "/verification/replay"
    provenance = _event_payload_row(
        "tr_snapshot_replay_drift",
        event_type="verification_replay",
        row_id=2,
        event_id="evt_snapshot_replay_provenance",
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        final_decision="blocked",
    )
    provenance_payload = provenance["payload"]
    assert isinstance(provenance_payload, dict)
    provenance_metadata = provenance_payload["metadata"]
    assert isinstance(provenance_metadata, dict)
    provenance_metadata["source_trace_id"] = "tr_snapshot_replay_source"
    provider = _StaticSnapshotProvider(
        run_rows=[run_row],
        event_rows=[provenance, completion],
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="replay event violates its contract"):
        ledger.export_snapshot(tenant_id="tenant-a")


def test_create_audit_ledger_postgres_requires_sql_provider(tmp_path: Path) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="SqlConnectionProvider"):
        create_audit_ledger(
            _postgres_settings(tmp_path),
            secret_manager=_AuditCommitmentSecretManager(),
        )


def test_audit_ledger_rejects_storage_path_and_storage_together(tmp_path: Path) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="not both"):
        AuditLedger(
            storage_path=tmp_path / "ledger.jsonl",
            storage=PostgresAuditLedgerStorage(connection=RecordingSqlProvider()),
        )


@pytest.mark.parametrize("export_max_records", [0, -1])
def test_audit_ledger_rejects_non_positive_export_cap(export_max_records: int) -> None:
    with pytest.raises(AuditLedgerConfigurationError, match="at least 1"):
        AuditLedger(export_max_records=export_max_records)


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


def test_local_export_snapshot_excludes_commit_between_former_reads() -> None:
    former_ledger = _local_ledger_with_commit_on_first_unlock()

    former_runs = former_ledger.export(tenant_id="tenant-a")
    former_events = former_ledger.export_events(tenant_id="tenant-a")

    assert [run.trace_id for run in former_runs] == ["tr_snapshot_local_initial"]
    assert [event.trace_id for event in former_events] == [
        "tr_snapshot_local_initial",
        "tr_snapshot_local_concurrent",
    ]

    ledger = _local_ledger_with_commit_on_first_unlock()

    snapshot = ledger.export_snapshot(tenant_id="tenant-a")

    assert [run.trace_id for run in snapshot.runs] == ["tr_snapshot_local_initial"]
    assert [event.trace_id for event in snapshot.events] == ["tr_snapshot_local_initial"]
    committed_snapshot = ledger.export_snapshot(tenant_id="tenant-a")
    assert [run.trace_id for run in committed_snapshot.runs] == [
        "tr_snapshot_local_initial",
        "tr_snapshot_local_concurrent",
    ]
    assert [event.trace_id for event in committed_snapshot.events] == [
        "tr_snapshot_local_initial",
        "tr_snapshot_local_concurrent",
    ]


def test_memory_completed_run_retry_returns_one_canonical_pair() -> None:
    ledger = AuditLedger()
    run = _verification_run()

    first = ledger.append_completed_run(run, path="/verification/run")
    retried = ledger.append_completed_run(run, path="/verification/run")

    assert retried == first
    assert retried.event.event_id == first.event.event_id
    assert ledger.export(tenant_id=run.tenant_id, trace_id=run.trace_id) == [first.run]
    assert ledger.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id) == [first.event]


@pytest.mark.parametrize("backend", ["memory", "jsonl"])
def test_completed_run_retry_rejects_conflicting_payload_without_partial_write(
    tmp_path: Path,
    backend: str,
) -> None:
    ledger = (
        AuditLedger()
        if backend == "memory"
        else AuditLedger(storage_path=tmp_path / "audit" / "ledger.jsonl")
    )
    run = _verification_run()
    ledger.append_completed_run(run, path="/verification/run")
    conflicting = run.model_copy(update={"final_text": "A different final response."})

    with pytest.raises(AuditLedgerStorageError, match="conflicts"):
        ledger.append_completed_run(conflicting, path="/verification/run")

    assert len(ledger.export(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 1
    assert len(ledger.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 1
    if backend == "jsonl":
        assert len((tmp_path / "audit" / "ledger.jsonl").read_text().splitlines()) == 1


@pytest.mark.parametrize("backend", ["memory", "jsonl"])
def test_same_trace_can_complete_once_per_compatible_verification_path(
    tmp_path: Path,
    backend: str,
) -> None:
    ledger = (
        AuditLedger()
        if backend == "memory"
        else AuditLedger(storage_path=tmp_path / "audit" / "ledger.jsonl")
    )
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_source_run"}})

    first = ledger.append_completed_run(run, path="/verification/run")
    replay = ledger.append_replayed_run(
        run,
        source_trace_id="tr_source_run",
        source_final_decision=run.final_decision,
    )

    assert first.event.event_id != replay.event.event_id
    assert len(ledger.export(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 2
    assert {
        event.path for event in ledger.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id)
    } == {"/verification/run", "/verification/replay"}
    assert len(ledger.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 3


@pytest.mark.parametrize("source_trace_id", ["", "tr_different_source"])
def test_replay_completion_rejects_invalid_or_mismatched_source_before_write(
    source_trace_id: str,
) -> None:
    ledger = AuditLedger()
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_expected_source"}})

    with pytest.raises(AuditLedgerStorageError, match="replay event"):
        ledger.append_replayed_run(
            run,
            source_trace_id=source_trace_id,
            source_final_decision=run.final_decision,
        )

    assert ledger.export() == []
    assert ledger.export_events() == []


@pytest.mark.parametrize("backend", ["memory", "jsonl"])
def test_completion_rejects_naive_run_timestamp_without_partial_write(
    tmp_path: Path,
    backend: str,
) -> None:
    ledger = (
        AuditLedger()
        if backend == "memory"
        else AuditLedger(storage_path=tmp_path / "audit" / "ledger.jsonl")
    )
    run = _verification_run().model_copy(update={"created_at": datetime(2026, 7, 11, 12, 0)})

    with pytest.raises(AuditLedgerStorageError, match="identity or timestamp"):
        ledger.append_completed_run(run, path="/verification/run")

    assert ledger.export() == []
    assert ledger.export_events() == []


def test_jsonl_completed_run_is_one_composite_record_and_reloads_atomically(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    run = _verification_run()

    first = ledger.append_completed_run(run, path="/verification/run")
    retried = ledger.append_completed_run(run, path="/verification/run")

    lines = storage_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["record_type"] == "verification_completion"
    assert set(record["payload"]) == {"event", "related_events", "run"}
    assert record["payload"]["related_events"] == []
    assert retried == first

    reloaded = AuditLedger(storage_path=storage_path)
    assert reloaded.export(tenant_id=run.tenant_id, trace_id=run.trace_id) == [first.run]
    assert reloaded.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id) == [first.event]


def test_jsonl_completion_persists_keyed_private_request_commitment(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    key = b"audit-test-key-32-bytes-minimum!!"
    run = _verification_run().model_copy(
        update={"input": {"token": "first-sensitive-original"}}
    )

    first = AuditLedger(
        storage_path=storage_path,
        request_commitment_key=key,
    ).append_completed_run(run, path="/verification/run")

    record = json.loads(storage_path.read_text(encoding="utf-8"))
    stored_run = record["payload"]["run"]
    commitment = stored_run[AUDIT_REQUEST_COMMITMENT_STORAGE_KEY]
    assert commitment.startswith("hmac-sha256:")
    assert len(commitment) == len("hmac-sha256:") + 64
    assert AUDIT_REQUEST_COMMITMENT_STORAGE_KEY not in first.run.model_dump(mode="json")
    assert "first-sensitive-original" not in storage_path.read_text(encoding="utf-8")

    reloaded = AuditLedger(
        storage_path=storage_path,
        request_commitment_key=key,
    )
    retried = reloaded.append_completed_run(run, path="/verification/run")
    assert retried.run.model_dump(mode="json") == first.run.model_dump(mode="json")
    assert len(storage_path.read_text(encoding="utf-8").splitlines()) == 1


def test_completion_rejects_distinct_sensitive_originals_with_same_projection() -> None:
    key = b"audit-test-key-32-bytes-minimum!!"
    ledger = AuditLedger(request_commitment_key=key)
    first = _verification_run().model_copy(
        update={"input": {"token": "first-sensitive-original"}}
    )
    second = first.model_copy(
        update={"input": {"token": "second-sensitive-original"}}
    )

    persisted = ledger.append_completed_run(first, path="/verification/run")
    assert persisted.run.input == {"token": REDACTED}

    with pytest.raises(AuditLedgerStorageError, match="original request commitment"):
        ledger.append_completed_run(second, path="/verification/run")

    assert len(ledger.export(tenant_id=first.tenant_id, trace_id=first.trace_id)) == 1


def test_sensitive_legacy_completion_without_commitment_fails_closed(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    key = b"audit-test-key-32-bytes-minimum!!"
    run = _verification_run().model_copy(
        update={"input": {"token": "legacy-sensitive-original"}}
    )
    canonical = AuditLedger(request_commitment_key=key).append_completed_run(
        run,
        path="/verification/run",
    )
    legacy_record = {
        "record_type": "verification_completion",
        "payload": {
            "run": canonical.run.model_dump(mode="json"),
            "event": canonical.event.model_dump(mode="json"),
            "related_events": [],
        },
    }
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(json.dumps(legacy_record) + "\n", encoding="utf-8")

    reloaded = AuditLedger(
        storage_path=storage_path,
        request_commitment_key=key,
    )
    with pytest.raises(AuditLedgerStorageError, match="missing its original"):
        reloaded.append_completed_run(run, path="/verification/run")


def test_audit_redaction_fails_closed_on_non_finite_payload_without_write(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    run = _verification_run().model_copy(update={"input": {"score": math.nan}})

    with pytest.raises(AuditLedgerStorageError, match="redacted completely"):
        AuditLedger(storage_path=storage_path).append_completed_run(
            run,
            path="/verification/run",
        )

    assert not storage_path.exists()


def test_jsonl_replay_triple_reloads_and_retries_without_new_records(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_secret_source"}})
    first = ledger.append_replayed_run(
        run,
        source_trace_id="tr_secret_source",
        source_final_decision=run.final_decision,
    )

    reloaded = AuditLedger(storage_path=storage_path)
    retried = reloaded.append_replayed_run(
        run,
        source_trace_id="tr_secret_source",
        source_final_decision=run.final_decision,
    )

    assert retried == first
    assert retried.run.input["replay_of"] == "tr_secret_source"
    assert retried.related_events[0].metadata["source_trace_id"] == "tr_secret_source"
    assert len(storage_path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(reloaded.export(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 1
    assert len(reloaded.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 2


def test_replay_run_and_both_events_cross_typed_redaction_seams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_calls: list[str] = []
    event_calls: list[str] = []
    original_run_redactor = audit_service._redact_verification_run
    original_event_redactor = audit_service._redact_audit_event

    def record_run(run: VerificationRun) -> VerificationRun:
        run_calls.append(run.trace_id)
        return original_run_redactor(run)

    def record_event(event: AuditEvent) -> AuditEvent:
        event_calls.append(event.event_type)
        return original_event_redactor(event)

    monkeypatch.setattr(audit_service, "_redact_verification_run", record_run)
    monkeypatch.setattr(audit_service, "_redact_audit_event", record_event)
    run = _verification_run().model_copy(
        update={"input": {"replay_of": "tr_secret_structural_source"}}
    )

    persisted = AuditLedger().append_replayed_run(
        run,
        source_trace_id="tr_secret_structural_source",
        source_final_decision=run.final_decision,
    )

    assert run_calls == [run.trace_id]
    assert event_calls == ["verification_completed", "verification_replay"]
    assert persisted.run.input["replay_of"] == "tr_secret_structural_source"
    assert persisted.related_events[0].metadata["source_trace_id"] == "tr_secret_structural_source"


def test_jsonl_replay_retry_adopts_legacy_compound_and_separate_event(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_legacy_replay_source"}})
    canonical = AuditLedger().append_replayed_run(
        run,
        source_trace_id="tr_legacy_replay_source",
        source_final_decision=run.final_decision,
    )
    legacy_records = [
        {
            "record_type": "verification_completion",
            "payload": {
                "run": canonical.run.model_dump(mode="json"),
                "event": canonical.event.model_dump(mode="json"),
            },
        },
        {
            "record_type": "audit_event",
            "payload": canonical.related_events[0].model_dump(mode="json"),
        },
    ]
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(
        "".join(json.dumps(record) + "\n" for record in legacy_records),
        encoding="utf-8",
    )

    reloaded = AuditLedger(storage_path=storage_path)
    retried = reloaded.append_replayed_run(
        run,
        source_trace_id="tr_legacy_replay_source",
        source_final_decision=run.final_decision,
    )

    assert retried.run.model_dump(mode="json") == canonical.run.model_dump(mode="json")
    assert retried.event == canonical.event
    assert retried.related_events == canonical.related_events
    assert len(storage_path.read_text(encoding="utf-8").splitlines()) == 2


def test_jsonl_replay_retry_adopts_legacy_run_and_provenance_without_completion(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_legacy_source_only"}})
    canonical = AuditLedger().append_replayed_run(
        run,
        source_trace_id="tr_legacy_source_only",
        source_final_decision=run.final_decision,
    )
    legacy_records = [
        {"record_type": "verification_run", "payload": canonical.run.model_dump(mode="json")},
        {
            "record_type": "audit_event",
            "payload": canonical.related_events[0].model_dump(mode="json"),
        },
    ]
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(
        "".join(json.dumps(record) + "\n" for record in legacy_records),
        encoding="utf-8",
    )

    reloaded = AuditLedger(storage_path=storage_path)
    retried = reloaded.append_replayed_run(
        run,
        source_trace_id="tr_legacy_source_only",
        source_final_decision=run.final_decision,
    )

    assert retried.run.model_dump(mode="json") == canonical.run.model_dump(mode="json")
    assert retried.related_events == canonical.related_events
    assert retried.event.event_type == "verification_completed"
    assert retried.event.metadata == {"final_decision": run.final_decision.value}
    assert len(reloaded.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 2
    assert len(storage_path.read_text(encoding="utf-8").splitlines()) == 2


def test_jsonl_legacy_replay_completion_preserves_newest_event_cap_order(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    replay_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    run = _verification_run().model_copy(
        update={
            "input": {"replay_of": "tr_legacy_cap_source"},
            "created_at": replay_at,
        }
    )
    canonical = AuditLedger().append_replayed_run(
        run,
        source_trace_id="tr_legacy_cap_source",
        source_final_decision=run.final_decision,
    )
    provenance = canonical.related_events[0].model_copy(update={"created_at": replay_at})
    later_event = AuditEvent(
        event_id="evt_legacy_cap_later",
        trace_id="tr_legacy_cap_later",
        tenant_id=run.tenant_id,
        event_type="http_request",
        method="GET",
        path="/health",
        status_code=200,
        outcome="success",
        created_at=later_at,
    )
    records = [
        {"record_type": "verification_run", "payload": canonical.run.model_dump(mode="json")},
        {"record_type": "audit_event", "payload": provenance.model_dump(mode="json")},
        {"record_type": "audit_event", "payload": later_event.model_dump(mode="json")},
    ]
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    reloaded = AuditLedger(storage_path=storage_path, export_max_records=1)

    assert reloaded.export_events(tenant_id=run.tenant_id) == [later_event]
    all_events = reloaded.page_events(
        tenant_id=run.tenant_id,
        event_type="verification_completed",
        limit=10,
    )
    assert len(all_events) == 1
    assert all_events[0].created_at == replay_at


def test_jsonl_reload_rejects_completion_decision_that_disagrees_with_run(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    ledger.append_completed_run(_verification_run(), path="/verification/run")
    record = json.loads(storage_path.read_text(encoding="utf-8"))
    record["payload"]["event"]["metadata"]["final_decision"] = "blocked"
    storage_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(AuditLedgerStorageError, match="does not match"):
        AuditLedger(storage_path=storage_path)


def test_jsonl_integrity_error_does_not_chain_invalid_enum_payload(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    ledger = AuditLedger(storage_path=storage_path)
    ledger.append_completed_run(_verification_run(), path="/verification/run")
    marker = "database-password-marker-must-not-leak"
    record = json.loads(storage_path.read_text(encoding="utf-8"))
    record["payload"]["event"]["metadata"]["final_decision"] = marker
    storage_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(AuditLedgerStorageError) as error:
        AuditLedger(storage_path=storage_path)

    rendered = "".join(
        traceback.format_exception(
            type(error.value),
            error.value,
            error.value.__traceback__,
        )
    )
    assert marker not in rendered
    assert error.value.__cause__ is None


def test_jsonl_reload_rejects_duplicate_legacy_completion_events(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    run = _verification_run()
    event = AuditEvent(
        event_id="evt_legacy_one",
        trace_id=run.trace_id,
        tenant_id=run.tenant_id,
        event_type="verification_completed",
        method="POST",
        path="/verification/run",
        status_code=200,
        outcome="success",
        metadata={"final_decision": run.final_decision.value},
        created_at=run.created_at,
    )
    records = [
        {"record_type": "verification_run", "payload": run.model_dump(mode="json")},
        {"record_type": "audit_event", "payload": event.model_dump(mode="json")},
        {
            "record_type": "audit_event",
            "payload": event.model_copy(update={"event_id": "evt_legacy_two"}).model_dump(
                mode="json"
            ),
        },
    ]
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    with pytest.raises(AuditLedgerStorageError, match="duplicate"):
        AuditLedger(storage_path=storage_path)


def test_jsonl_reload_rejects_duplicate_event_id_within_tenant(tmp_path: Path) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    event = AuditEvent(
        event_id="evt_duplicate_identity",
        trace_id="tr_duplicate_event_one",
        tenant_id="tenant-a",
        event_type="http_request",
        method="GET",
        path="/health",
        status_code=200,
        outcome="success",
        created_at=TEST_RETRIEVED_AT,
    )
    records = [
        {"record_type": "audit_event", "payload": event.model_dump(mode="json")},
        {
            "record_type": "audit_event",
            "payload": event.model_copy(update={"trace_id": "tr_duplicate_event_two"}).model_dump(
                mode="json"
            ),
        },
    ]
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    with pytest.raises(AuditLedgerStorageError, match="duplicate tenant event ID"):
        AuditLedger(storage_path=storage_path)


def test_jsonl_reload_does_not_expose_invalid_payload_in_validation_error(
    tmp_path: Path,
) -> None:
    storage_path = tmp_path / "audit" / "ledger.jsonl"
    marker = "database-password-marker-must-not-leak"
    record = {
        "record_type": "verification_run",
        "payload": {"final_decision": {"secret": marker}},
    }
    storage_path.parent.mkdir(parents=True)
    storage_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(AuditLedgerStorageError) as error:
        AuditLedger(storage_path=storage_path)

    assert marker not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize("backend", ["memory", "jsonl"])
def test_completed_run_concurrent_retry_is_exactly_once(
    tmp_path: Path,
    backend: str,
) -> None:
    ledger = (
        AuditLedger()
        if backend == "memory"
        else AuditLedger(storage_path=tmp_path / "audit" / "ledger.jsonl")
    )
    run = _verification_run()
    worker_count = 32
    barrier = threading.Barrier(worker_count)

    def append_once() -> CompletedVerificationRecord:
        barrier.wait()
        return ledger.append_completed_run(run, path="/verification/run")

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        records = list(pool.map(lambda _index: append_once(), range(worker_count)))

    event_ids = {record.event.event_id for record in records}
    assert len(event_ids) == 1
    assert len(ledger.export(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 1
    assert len(ledger.export_events(tenant_id=run.tenant_id, trace_id=run.trace_id)) == 1
    if backend == "jsonl":
        assert len((tmp_path / "audit" / "ledger.jsonl").read_text().splitlines()) == 1


def test_append_event_rejects_verification_completed_outside_atomic_boundary() -> None:
    ledger = AuditLedger()

    with pytest.raises(AuditLedgerError, match="append_completed_run"):
        ledger.append_event(
            trace_id="tr_forbidden_completion",
            tenant_id="tenant-a",
            event_type="verification_completed",
            method="POST",
            path="/verification/run",
            status_code=200,
            outcome="success",
            metadata={"final_decision": "allow"},
        )

    assert ledger.export() == []
    assert ledger.export_events() == []


def test_postgres_completed_run_uses_two_conflict_safe_inserts_in_one_transaction() -> None:
    provider = _AtomicAuditProvider()
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    persisted = ledger.append_completed_run(_verification_run(), path="/verification/run")

    insert_calls = [call for call in provider.calls if call[0] == "execute_returning"]
    assert len(insert_calls) == 2
    assert insert_calls[0][1].startswith("INSERT INTO audit_runs")
    assert insert_calls[1][1].startswith("INSERT INTO audit_events")
    assert all("ON CONFLICT DO NOTHING" in statement for _, statement, _ in insert_calls)
    assert all("RETURNING id, tenant_id, trace_id" in statement for _, statement, _ in insert_calls)
    assert provider.transaction_count == 1
    assert provider.commit_count == 1
    assert provider.rollback_count == 0
    assert list(provider.run_rows) == [
        (persisted.run.tenant_id, persisted.run.trace_id, persisted.event.path)
    ]
    assert list(provider.event_rows) == [
        (
            persisted.event.tenant_id,
            persisted.event.trace_id,
            persisted.event.event_type,
            persisted.event.path,
        )
    ]


def test_postgres_completed_run_second_insert_failure_rolls_back_the_run() -> None:
    provider = _AtomicAuditProvider(event_insert_error=RuntimeError("event insert failed"))
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(RuntimeError, match="event insert failed"):
        ledger.append_completed_run(_verification_run(), path="/verification/run")

    assert provider.run_rows == {}
    assert provider.event_rows == {}
    assert provider.commit_count == 0
    assert provider.rollback_count == 1


def test_postgres_completed_run_mixed_insert_result_rolls_back_the_run() -> None:
    provider = _AtomicAuditProvider(suppress_event_insert=True)
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="partial persisted pair"):
        ledger.append_completed_run(_verification_run(), path="/verification/run")

    assert provider.run_rows == {}
    assert provider.event_rows == {}
    assert provider.commit_count == 0
    assert provider.rollback_count == 1


def test_postgres_completed_run_zero_zero_retry_loads_existing_canonical_pair() -> None:
    provider = _AtomicAuditProvider()
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))
    run = _verification_run()

    first = ledger.append_completed_run(run, path="/verification/run")
    provider.calls.clear()
    retried = ledger.append_completed_run(run, path="/verification/run")

    assert retried == first
    assert retried.event.event_id == first.event.event_id
    assert [method for method, _statement, _parameters in provider.calls] == [
        "execute_returning",
        "execute_returning",
        "fetch_all",
        "fetch_all",
    ]
    assert provider.transaction_count == 2
    assert provider.commit_count == 2
    assert provider.rollback_count == 0
    assert len(provider.run_rows) == 1
    assert len(provider.event_rows) == 1


@pytest.mark.parametrize("duplicate_retry_select", ["run", "event"])
def test_postgres_completed_run_retry_rejects_duplicate_canonical_rows(
    duplicate_retry_select: str,
) -> None:
    provider = _AtomicAuditProvider(duplicate_retry_select=duplicate_retry_select)
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))
    run = _verification_run()
    ledger.append_completed_run(run, path="/verification/run")

    with pytest.raises(AuditLedgerStorageError, match="incomplete or duplicate unit"):
        ledger.append_completed_run(run, path="/verification/run")

    assert provider.commit_count == 1
    assert provider.rollback_count == 1
    assert len(provider.run_rows) == 1
    assert len(provider.event_rows) == 1


def test_postgres_replay_completion_is_one_exactly_once_three_record_transaction() -> None:
    provider = _AtomicAuditProvider()
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_replay_source"}})

    first = ledger.append_replayed_run(
        run,
        source_trace_id="tr_replay_source",
        source_final_decision=run.final_decision,
    )
    provider.calls.clear()
    retried = ledger.append_replayed_run(
        run,
        source_trace_id="tr_replay_source",
        source_final_decision=run.final_decision,
    )

    assert retried == first
    assert len(first.related_events) == 1
    assert first.related_events[0].event_type == "verification_replay"
    assert [method for method, _statement, _parameters in provider.calls] == [
        "execute_returning",
        "execute_returning",
        "execute_returning",
        "fetch_all",
        "fetch_all",
        "fetch_all",
    ]
    assert provider.transaction_count == 2
    assert provider.commit_count == 2
    assert provider.rollback_count == 0
    assert len(provider.run_rows) == 1
    assert len(provider.event_rows) == 2


def test_postgres_replay_third_insert_conflict_rolls_back_whole_unit() -> None:
    provider = _AtomicAuditProvider(suppress_event_type="verification_replay")
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))
    run = _verification_run().model_copy(update={"input": {"replay_of": "tr_replay_source"}})

    with pytest.raises(AuditLedgerStorageError, match="partial persisted pair"):
        ledger.append_replayed_run(
            run,
            source_trace_id="tr_replay_source",
            source_final_decision=run.final_decision,
        )

    assert provider.run_rows == {}
    assert provider.event_rows == {}
    assert provider.commit_count == 0
    assert provider.rollback_count == 1


@pytest.mark.parametrize(
    ("requested_tenant", "requested_trace", "match"),
    [
        ("tenant-other", "tr_scope", "tenant filter"),
        ("tenant-a", "tr_other", "trace filter"),
    ],
)
def test_postgres_export_rejects_rows_outside_requested_scope(
    requested_tenant: str,
    requested_trace: str,
    match: str,
) -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[_run_payload_row("tr_scope", tenant_id="tenant-a")]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match=match):
        ledger.export(tenant_id=requested_tenant, trace_id=requested_trace)


@pytest.mark.parametrize(
    ("requested_tenant", "requested_trace", "match"),
    [
        ("tenant-other", "tr_event_scope", "tenant filter"),
        ("tenant-a", "tr_event_other", "trace filter"),
    ],
)
def test_postgres_event_export_rejects_rows_outside_requested_scope(
    requested_tenant: str,
    requested_trace: str,
    match: str,
) -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[_event_payload_row("tr_event_scope", tenant_id="tenant-a")]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match=match):
        ledger.export_events(tenant_id=requested_tenant, trace_id=requested_trace)


@pytest.mark.parametrize("envelope_field", ["tenant_id", "trace_id", "created_at"])
def test_postgres_run_export_rejects_mismatched_envelope(envelope_field: str) -> None:
    row = _run_payload_row("tr_envelope")
    row[envelope_field] = {
        "tenant_id": "tenant-other",
        "trace_id": "tr_other",
        "created_at": datetime(2026, 2, 1, tzinfo=timezone.utc),
    }[envelope_field]
    provider = RecordingSqlProvider(fetch_all_rows=[row])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match=f"mismatched {envelope_field}"):
        ledger.export()


def test_postgres_run_export_rejects_invalid_completion_path() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _run_payload_row(
                "tr_invalid_completion_path",
                completion_path="/not-a-verification-path",
            )
        ]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="invalid completion path"):
        ledger.export(tenant_id="tenant-a")


def test_postgres_event_export_rejects_mismatched_event_id_envelope() -> None:
    row = _event_payload_row("tr_event_envelope")
    row["event_id"] = "evt_other"
    provider = RecordingSqlProvider(fetch_all_rows=[row])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="mismatched event_id"):
        ledger.export_events()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", "GET"),
        ("path", "/not-a-verification-path"),
        ("status_code", 201),
        ("outcome", "error"),
        ("metadata", {"final_decision": "not-a-decision"}),
        ("metadata", {"final_decision": "allow", "unexpected": "not-allowed"}),
    ],
)
def test_postgres_event_export_rejects_invalid_completion_contract(
    field: str,
    value: object,
) -> None:
    row = _event_payload_row("tr_invalid_completion", event_type="verification_completed")
    payload_object = row["payload"]
    assert isinstance(payload_object, Mapping)
    payload = dict(payload_object)
    payload[field] = value
    row["payload"] = payload
    provider = RecordingSqlProvider(fetch_all_rows=[row])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="completion event"):
        ledger.export_events(tenant_id="tenant-a", trace_id="tr_invalid_completion")


def test_postgres_event_export_rejects_invalid_replay_contract() -> None:
    row = _event_payload_row("tr_invalid_replay", event_type="verification_replay")
    payload_object = row["payload"]
    assert isinstance(payload_object, Mapping)
    payload = dict(payload_object)
    metadata_object = payload["metadata"]
    assert isinstance(metadata_object, Mapping)
    metadata = dict(metadata_object)
    metadata["unexpected"] = "not-allowed"
    payload["metadata"] = metadata
    row["payload"] = payload
    provider = RecordingSqlProvider(fetch_all_rows=[row])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="replay event"):
        ledger.export_events(tenant_id="tenant-a", trace_id="tr_invalid_replay")


def test_postgres_export_rejects_provider_rows_over_limit() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _run_payload_row(
                "tr_newer", row_id=2, created_at=datetime(2026, 1, 2, tzinfo=timezone.utc)
            ),
            _run_payload_row(
                "tr_older", row_id=1, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
            ),
        ]
    )
    ledger = AuditLedger(
        storage=PostgresAuditLedgerStorage(connection=provider),
        export_max_records=1,
    )

    with pytest.raises(AuditLedgerStorageError, match="exceeded its requested limit"):
        ledger.export(tenant_id="tenant-a")


def test_postgres_event_export_rejects_provider_rows_over_limit() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _event_payload_row(
                "tr_event_newer",
                row_id=2,
                event_id="evt_event_newer",
                created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            _event_payload_row(
                "tr_event_older",
                row_id=1,
                event_id="evt_event_older",
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ]
    )
    ledger = AuditLedger(
        storage=PostgresAuditLedgerStorage(connection=provider),
        export_max_records=1,
    )

    with pytest.raises(AuditLedgerStorageError, match="exceeded its requested limit"):
        ledger.export_events(tenant_id="tenant-a")


def test_postgres_export_rejects_rows_not_in_database_order() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _run_payload_row(
                "tr_older", row_id=1, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
            ),
            _run_payload_row(
                "tr_newer", row_id=2, created_at=datetime(2026, 1, 2, tzinfo=timezone.utc)
            ),
        ]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="violates export ordering"):
        ledger.export(tenant_id="tenant-a")


def test_postgres_export_rejects_duplicate_database_ordering_key() -> None:
    row = _run_payload_row("tr_duplicate_export")
    provider = RecordingSqlProvider(fetch_all_rows=[row, dict(row)])
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="duplicate database row ID"):
        ledger.export(tenant_id="tenant-a")


def test_postgres_export_rejects_duplicate_database_id_with_distinct_timestamps() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _run_payload_row(
                "tr_duplicate_id_newer",
                row_id=7,
                created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            _run_payload_row(
                "tr_duplicate_id_older",
                row_id=7,
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="duplicate database row ID"):
        ledger.export(tenant_id="tenant-a")


def test_postgres_event_export_rejects_duplicate_tenant_event_id() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            _event_payload_row(
                "tr_duplicate_event_newer",
                row_id=2,
                event_id="evt_duplicate_export_identity",
                created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            _event_payload_row(
                "tr_duplicate_event_older",
                row_id=1,
                event_id="evt_duplicate_export_identity",
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ]
    )
    ledger = AuditLedger(storage=PostgresAuditLedgerStorage(connection=provider))

    with pytest.raises(AuditLedgerStorageError, match="duplicate tenant event ID"):
        ledger.export_events(tenant_id="tenant-a")


class _CommitOnFirstReleaseLock:
    def __init__(self, on_first_release: Callable[[], None]) -> None:
        self._lock = threading.Lock()
        self._on_first_release = on_first_release
        self._released_once = False

    def __enter__(self) -> _CommitOnFirstReleaseLock:
        self._lock.acquire()
        return self

    def __exit__(
        self,
        exc_type: object,
        _exc: object,
        _traceback: object,
    ) -> None:
        self._lock.release()
        if exc_type is None and not self._released_once:
            self._released_once = True
            self._on_first_release()


def _local_ledger_with_commit_on_first_unlock() -> AuditLedger:
    ledger = AuditLedger()
    initial_run = _verification_run().model_copy(
        update={
            "trace_id": "tr_snapshot_local_initial",
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
    )
    concurrent_run = _verification_run().model_copy(
        update={
            "trace_id": "tr_snapshot_local_concurrent",
            "created_at": datetime(2026, 1, 2, tzinfo=timezone.utc),
        }
    )
    ledger.append_completed_run(initial_run, path="/verification/run")

    def commit_concurrent_pair() -> None:
        ledger.append_completed_run(concurrent_run, path="/verification/run")

    setattr(ledger, "_lock", _CommitOnFirstReleaseLock(commit_concurrent_pair))
    return ledger


class _InterleavingSnapshotProvider:
    """Stateful fake that commits a pair after the run SELECT returns."""

    def __init__(self, *, initial_event_decision: str = "allow") -> None:
        initial_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        concurrent_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.live_run_rows = [
            _run_payload_row(
                "tr_snapshot_initial",
                row_id=1,
                created_at=initial_at,
                completion_path="/verification/run",
            )
        ]
        self.live_event_rows = [
            _event_payload_row(
                "tr_snapshot_initial",
                event_type="verification_completed",
                row_id=1,
                event_id="evt_snapshot_initial",
                created_at=initial_at,
                final_decision=initial_event_decision,
            )
        ]
        self._concurrent_run = _run_payload_row(
            "tr_snapshot_concurrent",
            row_id=2,
            created_at=concurrent_at,
            completion_path="/verification/run",
        )
        self._concurrent_event = _event_payload_row(
            "tr_snapshot_concurrent",
            event_type="verification_completed",
            row_id=2,
            event_id="evt_snapshot_concurrent",
            created_at=concurrent_at,
        )
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.transaction_count = 0
        self.external_commit_count = 0
        self.base_fetch_count = 0

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        raise AssertionError(f"Unexpected base execute statement: {statement}")

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        self.base_fetch_count += 1
        self.calls.append(("base_fetch_all", statement, tuple(parameters)))
        rows = self._rows_for(statement, self.live_run_rows, self.live_event_rows)
        if "FROM audit_runs" in statement:
            self._commit_external_pair()
        return rows

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        raise AssertionError(f"Unexpected execute_returning statement: {statement}")

    @contextmanager
    def transaction(self) -> Iterator[_InterleavingSnapshotTransaction]:
        self.transaction_count += 1
        self.calls.append(("transaction_enter", "", ()))
        transaction = _InterleavingSnapshotTransaction(self)
        try:
            yield transaction
        finally:
            self.calls.append(("transaction_exit", "", ()))

    def _commit_external_pair(self) -> None:
        if self.external_commit_count:
            return
        self.external_commit_count += 1
        self.live_run_rows.append(dict(self._concurrent_run))
        self.live_event_rows.append(dict(self._concurrent_event))
        self.calls.append(("external_commit", "", ()))

    @staticmethod
    def _rows_for(
        statement: str,
        run_rows: Sequence[Mapping[str, object]],
        event_rows: Sequence[Mapping[str, object]],
    ) -> list[Mapping[str, object]]:
        if "FROM audit_runs" in statement:
            rows = run_rows
        elif "FROM audit_events" in statement:
            rows = event_rows
        else:
            raise AssertionError(f"Unexpected fetch_all statement: {statement}")
        return sorted(
            (dict(row) for row in rows),
            key=lambda row: (
                _required_datetime(row["created_at"]),
                _required_int(row["id"]),
            ),
            reverse=True,
        )


class _InterleavingSnapshotTransaction:
    def __init__(self, parent: _InterleavingSnapshotProvider) -> None:
        self._parent = parent
        self._run_snapshot: list[Mapping[str, object]] | None = None
        self._event_snapshot: list[Mapping[str, object]] | None = None

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        self._parent.calls.append(("transaction_execute", statement, tuple(parameters)))
        assert statement == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        assert tuple(parameters) == ()
        assert self._run_snapshot is None
        self._run_snapshot = [dict(row) for row in self._parent.live_run_rows]
        self._event_snapshot = [dict(row) for row in self._parent.live_event_rows]

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        assert self._run_snapshot is not None
        assert self._event_snapshot is not None
        self._parent.calls.append(("transaction_fetch_all", statement, tuple(parameters)))
        rows = self._parent._rows_for(statement, self._run_snapshot, self._event_snapshot)
        if "FROM audit_runs" in statement:
            self._parent._commit_external_pair()
        return rows

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        raise AssertionError(f"Unexpected execute_returning statement: {statement}")

    @contextmanager
    def transaction(self) -> Iterator[_InterleavingSnapshotTransaction]:
        yield self


class _StaticSnapshotProvider:
    def __init__(
        self,
        *,
        run_rows: Sequence[Mapping[str, object]],
        event_rows: Sequence[Mapping[str, object]],
    ) -> None:
        self._run_rows = list(run_rows)
        self._event_rows = list(event_rows)
        self._isolation_set = False

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        assert statement == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        assert tuple(parameters) == ()
        self._isolation_set = True

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        del parameters
        assert self._isolation_set
        if "FROM audit_runs" in statement:
            return [dict(row) for row in self._run_rows]
        if "FROM audit_events" in statement:
            return [dict(row) for row in self._event_rows]
        raise AssertionError(f"Unexpected fetch_all statement: {statement}")

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        raise AssertionError(f"Unexpected execute_returning statement: {statement}")

    @contextmanager
    def transaction(self) -> Iterator[_StaticSnapshotProvider]:
        yield self


class _AtomicAuditProvider:
    """Stateful transaction fake for the exactly-once completion boundary."""

    def __init__(
        self,
        *,
        event_insert_error: Exception | None = None,
        suppress_event_insert: bool = False,
        suppress_event_type: str | None = None,
        duplicate_retry_select: str | None = None,
    ) -> None:
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.run_rows: dict[tuple[str, str, str], dict[str, object]] = {}
        self.event_rows: dict[tuple[str, str, str, str], dict[str, object]] = {}
        self.transaction_count = 0
        self.commit_count = 0
        self.rollback_count = 0
        self._next_run_id = 1
        self._next_event_id = 1
        self._event_insert_error = event_insert_error
        self._suppress_event_insert = suppress_event_insert
        self._suppress_event_type = suppress_event_type
        self._duplicate_retry_select = duplicate_retry_select
        self._lock = threading.RLock()

    def execute(self, statement: str, parameters: Sequence[object] = ()) -> None:
        self.calls.append(("execute", statement, tuple(parameters)))
        raise AssertionError(f"Unexpected execute statement: {statement}")

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        params = tuple(parameters)
        with self._lock:
            self.calls.append(("fetch_all", statement, params))
            if statement.startswith(
                "SELECT id, tenant_id, trace_id, completion_path, created_at, payload"
            ):
                row = self.run_rows.get(
                    (
                        _required_str(params[0]),
                        _required_str(params[1]),
                        _required_str(params[2]),
                    )
                )
                if row is None:
                    return []
                rows = [dict(row)]
                if self._duplicate_retry_select == "run":
                    rows.append(dict(row))
                return rows
            if statement.startswith(
                "SELECT id, tenant_id, trace_id, event_id, created_at, payload"
            ):
                row = self.event_rows.get(
                    (
                        _required_str(params[0]),
                        _required_str(params[1]),
                        _required_str(params[2]),
                        _required_str(params[3]),
                    )
                )
                if row is None:
                    return []
                rows = [dict(row)]
                if self._duplicate_retry_select == "event":
                    rows.append(dict(row))
                return rows
        raise AssertionError(f"Unexpected fetch_all statement: {statement}")

    def execute_returning(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> Sequence[Mapping[str, object]]:
        params = tuple(parameters)
        with self._lock:
            self.calls.append(("execute_returning", statement, params))
            if statement.startswith("INSERT INTO audit_runs"):
                run_key = (
                    _required_str(params[0]),
                    _required_str(params[1]),
                    _required_str(params[2]),
                )
                if run_key in self.run_rows:
                    return []
                payload = _required_payload(params[3])
                row = {
                    "id": self._next_run_id,
                    "tenant_id": run_key[0],
                    "trace_id": run_key[1],
                    "completion_path": run_key[2],
                    "created_at": _required_datetime(params[4]),
                    "payload": payload,
                }
                self._next_run_id += 1
                self.run_rows[run_key] = row
                return [dict(row)]
            if statement.startswith("INSERT INTO audit_events"):
                if self._event_insert_error is not None:
                    raise self._event_insert_error
                payload = _required_payload(params[3])
                event_type = _required_str(payload["event_type"])
                if self._suppress_event_insert or self._suppress_event_type == event_type:
                    return []
                event_key = (
                    _required_str(params[0]),
                    _required_str(params[1]),
                    event_type,
                    _required_str(payload["path"]),
                )
                if event_key in self.event_rows:
                    return []
                row = {
                    "id": self._next_event_id,
                    "tenant_id": event_key[0],
                    "trace_id": event_key[1],
                    "event_id": _required_str(params[2]),
                    "created_at": _required_datetime(params[4]),
                    "payload": payload,
                }
                self._next_event_id += 1
                self.event_rows[event_key] = row
                return [dict(row)]
        raise AssertionError(f"Unexpected execute_returning statement: {statement}")

    @contextmanager
    def transaction(self) -> Iterator[_AtomicAuditProvider]:
        with self._lock:
            run_snapshot = dict(self.run_rows)
            event_snapshot = dict(self.event_rows)
            run_id_snapshot = self._next_run_id
            event_id_snapshot = self._next_event_id
            self.transaction_count += 1
            try:
                yield self
            except BaseException:
                self.run_rows = run_snapshot
                self.event_rows = event_snapshot
                self._next_run_id = run_id_snapshot
                self._next_event_id = event_id_snapshot
                self.rollback_count += 1
                raise
            else:
                self.commit_count += 1


def _required_str(value: object) -> str:
    assert isinstance(value, str)
    return value


def _required_datetime(value: object) -> datetime:
    assert isinstance(value, datetime)
    return value


def _required_int(value: object) -> int:
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


def _required_payload(value: object) -> dict[str, object]:
    assert isinstance(value, str)
    payload = json.loads(value)
    assert isinstance(payload, dict)
    return payload


def _postgres_settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="production",
        policy_version="test",
        auth_required=True,
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        audit_ledger_backend="postgres",
        secrets_backend="vault",
        audit_request_commitment_secret_name="audit/request-commitment-key",
    )


def _run_payload_row(
    trace_id: str,
    *,
    row_id: int = 1,
    tenant_id: str = "tenant-a",
    created_at: datetime | None = None,
    completion_path: str | None = None,
) -> dict[str, object]:
    run = _verification_run().model_copy(
        update={
            "trace_id": trace_id,
            "tenant_id": tenant_id,
            "created_at": created_at or TEST_RETRIEVED_AT,
        }
    )
    row: dict[str, object] = {
        "id": row_id,
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "completion_path": completion_path,
        "created_at": run.created_at,
        "payload": run.model_dump(mode="json"),
    }
    return row


def _event_payload_row(
    trace_id: str,
    *,
    event_type: str = "http_request",
    row_id: int = 1,
    tenant_id: str = "tenant-a",
    event_id: str = "evt_row",
    created_at: datetime | None = None,
    final_decision: str = "allow",
) -> dict[str, object]:
    completion = event_type == "verification_completed"
    replay = event_type == "verification_replay"
    event = AuditEvent(
        event_id=event_id,
        trace_id=trace_id,
        tenant_id=tenant_id,
        event_type=event_type,
        method="POST" if completion or replay else "GET",
        path=(
            "/verification/run" if completion else "/verification/replay" if replay else "/health"
        ),
        status_code=200,
        outcome="success",
        metadata=(
            {"final_decision": final_decision}
            if completion
            else {
                "source_trace_id": "tr_replay_source",
                "source_final_decision": final_decision,
                "replay_final_decision": final_decision,
                "decision_changed": False,
            }
            if replay
            else {}
        ),
        created_at=created_at or TEST_RETRIEVED_AT,
    )
    row: dict[str, object] = {
        "id": row_id,
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "event_id": event_id,
        "created_at": event.created_at,
        "payload": event.model_dump(mode="json"),
    }
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
                source_ref="audit-source",
                content="This evidence mentions token handling.",
                structured_content={},
                authority=Authority.UNKNOWN,
                freshness=Freshness(
                    retrieved_at=TEST_RETRIEVED_AT,
                    staleness_class=StalenessClass.UNKNOWN,
                ),
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


def _ownership_verification_run(*, trace_id: str) -> VerificationRun:
    return VerificationRun(
        trace_id=trace_id,
        tenant_id="tenant-a",
        input={"nested": {"values": ["ingress-original"]}},
        claims=[
            Claim(
                claim_id="clm_owned",
                text="Ownership test claim.",
                canonical_form="Ownership canonical form.",
                source_span=SourceSpan(
                    message_id="msg_owned",
                    start_char=0,
                    end_char=4,
                ),
                metadata={"nested": {"values": ["claim-original"]}},
            )
        ],
        evidence=[
            Evidence(
                evidence_id="ev_owned",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="ownership-source",
                content="Ownership evidence.",
                structured_content={"nested": {"values": ["evidence-original"]}},
                authority=Authority.UNKNOWN,
                freshness=Freshness(
                    retrieved_at=TEST_RETRIEVED_AT,
                    staleness_class=StalenessClass.UNKNOWN,
                ),
            )
        ],
        verdicts=[
            ClaimVerdict(
                claim_id="clm_owned",
                status=VerdictStatus.SUPPORTED,
                confidence=0.9,
                evidence_ids=["ev_owned"],
                action=VerdictAction.ALLOW,
                reason="Ownership evidence supports the claim.",
                validator_trace={"nested": {"values": ["verdict-original"]}},
            )
        ],
        final_decision=FinalDecision.ALLOW,
        final_text="Ownership final text.",
        policy_version="test",
    )


def _ledger_snapshot_payload(ledger: AuditLedger) -> dict[str, object]:
    snapshot = ledger.export_snapshot(tenant_id="tenant-a")
    return {
        "runs": [run.model_dump(mode="json") for run in snapshot.runs],
        "events": [event.model_dump(mode="json") for event in snapshot.events],
    }


def _mutate_nested_values(mapping: dict[str, object], replacement: str) -> None:
    nested = mapping["nested"]
    assert isinstance(nested, dict)
    values = nested["values"]
    assert isinstance(values, list)
    values[0] = replacement


def _mutate_run_graph(run: VerificationRun, prefix: str) -> None:
    _mutate_nested_values(run.input, f"{prefix}-input")
    span = run.claims[0].source_span
    assert span is not None
    span.start_char = 1
    _mutate_nested_values(run.claims[0].metadata, f"{prefix}-claim")
    _mutate_nested_values(
        run.evidence[0].structured_content,
        f"{prefix}-evidence",
    )
    run.evidence[0].freshness.staleness_class = StalenessClass.STALE
    run.verdicts[0].evidence_ids[0] = f"{prefix}-evidence-id"
    _mutate_nested_values(
        run.verdicts[0].validator_trace,
        f"{prefix}-verdict",
    )


def _mutate_all_ledger_views(ledger: AuditLedger) -> None:
    exported_run = next(
        run for run in ledger.export(tenant_id="tenant-a") if run.trace_id == "tr_owned_source"
    )
    _mutate_run_graph(exported_run, "export")

    exported_event = next(
        event
        for event in ledger.export_events(tenant_id="tenant-a")
        if event.event_type == "ownership_nested"
    )
    _mutate_nested_values(exported_event.metadata, "export-event")

    snapshot = ledger.export_snapshot(tenant_id="tenant-a")
    snapshot_run = next(run for run in snapshot.runs if run.trace_id == "tr_owned_source")
    _mutate_run_graph(snapshot_run, "snapshot")
    snapshot_event = next(
        event for event in snapshot.events if event.event_type == "ownership_nested"
    )
    _mutate_nested_values(snapshot_event.metadata, "snapshot-event")

    source = ledger.find_replay_source(
        tenant_id="tenant-a",
        trace_id="tr_owned_source",
    )
    assert source is not None
    _mutate_run_graph(source, "source")

    paged_event = ledger.page_events(
        tenant_id="tenant-a",
        event_type="ownership_nested",
        limit=1,
    )[0]
    _mutate_nested_values(paged_event.metadata, "page-event")


@pytest.mark.parametrize("backend", ["memory", "jsonl"])
def test_audit_ledger_deeply_owns_ingress_storage_and_all_outward_models(
    tmp_path: Path,
    backend: str,
) -> None:
    ledger_path = tmp_path / "owned-audit.jsonl" if backend == "jsonl" else None
    ledger = AuditLedger(storage_path=ledger_path)
    source_run = _ownership_verification_run(trace_id="tr_owned_source")
    completed = ledger.append_completed_run(source_run, path="/verification/run")
    replay_run = _ownership_verification_run(trace_id="tr_owned_replay").model_copy(
        update={
            "input": {
                "replay_of": "tr_owned_source",
                "nested": {"values": ["replay-original"]},
            }
        },
        deep=True,
    )
    replayed = ledger.append_replayed_run(
        replay_run,
        source_trace_id="tr_owned_source",
        source_final_decision=FinalDecision.ALLOW,
    )
    caller_metadata: dict[str, object] = {"nested": {"values": ["event-original"]}}
    appended_event = ledger.append_event(
        trace_id="tr_owned_event",
        tenant_id="tenant-a",
        event_type="ownership_nested",
        method="POST",
        path="/ownership",
        status_code=200,
        outcome="success",
        metadata=caller_metadata,
    )
    baseline = _ledger_snapshot_payload(ledger)
    retried = ledger.append_completed_run(
        source_run.model_copy(deep=True),
        path="/verification/run",
    )
    assert _ledger_snapshot_payload(ledger) == baseline

    _mutate_run_graph(source_run, "caller")
    _mutate_run_graph(replay_run, "replay-caller")
    _mutate_run_graph(completed.run, "completion-return")
    completed.event.metadata["final_decision"] = "mutated"
    _mutate_run_graph(replayed.run, "replay-return")
    replayed.event.metadata["final_decision"] = "mutated"
    replayed.related_events[0].metadata["source_trace_id"] = "tr_mutated"
    _mutate_run_graph(retried.run, "retry-return")
    retried.event.metadata["final_decision"] = "mutated"
    _mutate_nested_values(caller_metadata, "caller-event")
    _mutate_nested_values(appended_event.metadata, "append-event-return")
    _mutate_all_ledger_views(ledger)

    assert _ledger_snapshot_payload(ledger) == baseline

    if ledger_path is not None:
        reloaded = AuditLedger(storage_path=ledger_path)
        reloaded_baseline = _ledger_snapshot_payload(reloaded)
        assert reloaded_baseline == baseline
        _mutate_all_ledger_views(reloaded)
        assert _ledger_snapshot_payload(reloaded) == reloaded_baseline
        assert _ledger_snapshot_payload(AuditLedger(storage_path=ledger_path)) == baseline
