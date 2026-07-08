from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.api import routes
from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    Authority,
    Claim,
    ClaimType,
    CorpusGrantDisableRequest,
    CorpusGrantHistoryDiffRequest,
    CorpusGrantHistoryRequest,
    CorpusGrantListRequest,
    CorpusGrantUpsertRequest,
    DocumentIngestionRequest,
    DocumentInput,
    Evidence,
    EvidenceKind,
    Freshness,
    RiskLevel,
    StalenessClass,
)
from hallu_defense.main import app
import hallu_defense.services.corpus_grants as corpus_grants_module
from hallu_defense.services.corpus_grants import (
    CorpusGrantConfigurationError,
    CorpusGrantRegistry,
    CorpusGrantStorageError,
    CorpusGrantVersionConflictError,
    PostgresCorpusGrantStorage,
    PsycopgCorpusGrantSqlConnection,
    create_corpus_grant_registry,
)
from hallu_defense.services.ingestion import DocumentIngestionService
from hallu_defense.services.rag_access import RagAccessDeniedError, RagAccessPolicy
from hallu_defense.services.rag_index import RagChunk, RagIndexWriteResult, RagSearchRequest
from hallu_defense.services.retrieval import HybridRetriever


def test_jsonl_corpus_grants_persist_reload_and_stay_tenant_scoped(tmp_path: Path) -> None:
    storage_path = tmp_path / "corpus-grants.jsonl"
    registry = CorpusGrantRegistry(storage_path=storage_path)

    created = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["hr_reader", "hr_reader"],
            writer_roles=["hr_writer"],
        ),
        updated_by="alice",
    )
    registry.upsert(
        tenant_id="tenant-b",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["other_reader"]),
        updated_by="mallory",
    )
    updated = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["finance_reader", "hr_reader"],
            writer_roles=["finance_writer"],
        ),
        updated_by="bob",
    )

    assert updated.created_by == "alice"
    assert updated.created_at == created.created_at
    assert updated.updated_by == "bob"
    assert updated.reader_roles == ["finance_reader", "hr_reader"]
    assert len(storage_path.read_text(encoding="utf-8").splitlines()) == 3

    reloaded = CorpusGrantRegistry(storage_path=storage_path)
    tenant_a_grants = reloaded.list_for_tenant("tenant-a", CorpusGrantListRequest()).grants

    assert [grant.corpus_id for grant in tenant_a_grants] == ["hr"]
    assert tenant_a_grants[0].tenant_id == "tenant-a"
    assert tenant_a_grants[0].reader_roles == ["finance_reader", "hr_reader"]
    assert tenant_a_grants[0].version == 2
    tenant_a_history = reloaded.history_for_tenant("tenant-a", CorpusGrantHistoryRequest()).grants
    assert [grant.version for grant in tenant_a_history] == [1, 2]
    assert [grant.reader_roles for grant in tenant_a_history] == [
        ["hr_reader"],
        ["finance_reader", "hr_reader"],
    ]
    assert reloaded.history_for_tenant("tenant-b", CorpusGrantHistoryRequest()).grants[0].version == 1
    assert reloaded.get(tenant_id="tenant-b", corpus_id="hr") is not None
    assert reloaded.get(tenant_id="tenant-a", corpus_id="missing") is None


def test_jsonl_corpus_grants_disable_reload_and_reenable(tmp_path: Path) -> None:
    storage_path = tmp_path / "corpus-grants.jsonl"
    registry = CorpusGrantRegistry(storage_path=storage_path)
    created = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["hr_reader"],
            writer_roles=["hr_writer"],
        ),
        updated_by="alice",
    )

    disabled = registry.disable(
        tenant_id="tenant-a",
        request=CorpusGrantDisableRequest(corpus_id="hr"),
        disabled_by="bob",
    )

    assert disabled.version == created.version + 1
    assert disabled.disabled_by == "bob"
    assert disabled.disabled_at is not None
    assert registry.get(tenant_id="tenant-a", corpus_id="hr") is None
    assert registry.list_for_tenant("tenant-a", CorpusGrantListRequest()).grants == []
    disabled_page = registry.list_for_tenant(
        "tenant-a",
        CorpusGrantListRequest(include_disabled=True),
    )
    assert disabled_page.grants[0].disabled_by == "bob"

    reloaded = CorpusGrantRegistry(storage_path=storage_path)
    assert reloaded.get(tenant_id="tenant-a", corpus_id="hr") is None
    reenabled = reloaded.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["new_reader"]),
        updated_by="carol",
    )

    assert reenabled.version == disabled.version + 1
    assert reenabled.created_by == "alice"
    assert reenabled.disabled_at is None
    assert reenabled.reader_roles == ["new_reader"]
    assert [grant.version for grant in reloaded.history_for_tenant("tenant-a", CorpusGrantHistoryRequest()).grants] == [
        1,
        2,
        3,
    ]
    assert len(storage_path.read_text(encoding="utf-8").splitlines()) == 3


def test_postgres_corpus_grants_storage_is_parameterized_and_reloads_history() -> None:
    connection = RecordingCorpusGrantSqlConnection()
    registry = CorpusGrantRegistry(
        storage=PostgresCorpusGrantStorage(
            table_name="rag_corpus_grants",
            connection=connection,
        )
    )

    created = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["hr_reader"],
            writer_roles=["hr_writer"],
        ),
        updated_by="alice",
    )
    updated = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["senior_hr_reader"],
            writer_roles=["hr_writer"],
            expected_version=created.version,
        ),
        updated_by="bob",
    )

    load_statement, load_parameters = connection.fetch_all_calls[0]
    assert load_statement == "SELECT payload FROM rag_corpus_grants ORDER BY sequence_id ASC"
    assert load_parameters == ()
    insert_statement, insert_parameters = connection.execute_calls[0]
    assert "INSERT INTO rag_corpus_grants" in insert_statement
    assert "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)" in insert_statement
    assert insert_parameters[:5] == [
        "tenant-a",
        "hr",
        1,
        ["hr_reader"],
        ["hr_writer"],
    ]
    assert isinstance(insert_parameters[-1], str)
    assert json.loads(insert_parameters[-1])["updated_by"] == "alice"

    reloaded_connection = RecordingCorpusGrantSqlConnection(
        rows=[
            {"payload": connection.execute_calls[0][1][-1]},
            {"payload": json.loads(connection.execute_calls[1][1][-1])},
        ]
    )
    reloaded = CorpusGrantRegistry(
        storage=PostgresCorpusGrantStorage(
            table_name="rag_corpus_grants",
            connection=reloaded_connection,
        )
    )
    history = reloaded.history_for_tenant("tenant-a", CorpusGrantHistoryRequest()).grants

    assert [grant.version for grant in history] == [1, 2]
    assert reloaded.get(tenant_id="tenant-a", corpus_id="hr") == updated


def test_postgres_corpus_grants_storage_fails_closed_on_invalid_payload() -> None:
    connection = RecordingCorpusGrantSqlConnection(rows=[{"payload": {"tenant_id": "tenant-a"}}])

    with pytest.raises(CorpusGrantStorageError, match="payload is invalid"):
        CorpusGrantRegistry(
            storage=PostgresCorpusGrantStorage(
                table_name="rag_corpus_grants",
                connection=connection,
            )
        )


def test_postgres_corpus_grants_storage_rejects_unsafe_table_name() -> None:
    with pytest.raises(CorpusGrantConfigurationError, match="identifier"):
        PostgresCorpusGrantStorage(
            table_name="rag_corpus_grants;drop",
            connection=RecordingCorpusGrantSqlConnection(),
        )


def test_psycopg_corpus_grants_connection_executes_and_fetches_mapping_rows() -> None:
    fake_connect = RecordingPsycopgConnect(rows=[{"payload": {"ok": True}}])
    connection = PsycopgCorpusGrantSqlConnection(
        dsn="postgresql://postgres@localhost/hallu_defense",
        connect=fake_connect,
        row_factory="dict_row",
    )

    connection.execute("INSERT INTO rag_corpus_grants VALUES (%s)", ["tenant-a"])
    rows = connection.fetch_all("SELECT payload FROM rag_corpus_grants", ())

    assert rows == [{"payload": {"ok": True}}]
    assert fake_connect.calls == [
        ("postgresql://postgres@localhost/hallu_defense", "dict_row"),
        ("postgresql://postgres@localhost/hallu_defense", "dict_row"),
    ]
    assert fake_connect.connections[0].cursor_instance.execute_calls == [
        ("INSERT INTO rag_corpus_grants VALUES (%s)", ["tenant-a"])
    ]
    assert fake_connect.connections[1].cursor_instance.execute_calls == [
        ("SELECT payload FROM rag_corpus_grants", ())
    ]


def test_corpus_grant_upsert_expected_version_prevents_stale_write() -> None:
    registry = CorpusGrantRegistry()

    created = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["hr_reader"],
            expected_version=0,
        ),
        updated_by="alice",
    )

    assert created.version == 1
    with pytest.raises(CorpusGrantVersionConflictError, match="expected 0, current 1"):
        registry.upsert(
            tenant_id="tenant-a",
            request=CorpusGrantUpsertRequest(
                corpus_id="hr",
                reader_roles=["finance_reader"],
                expected_version=0,
            ),
            updated_by="bob",
        )

    updated = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(
            corpus_id="hr",
            reader_roles=["finance_reader"],
            expected_version=created.version,
        ),
        updated_by="bob",
    )

    assert updated.version == 2
    assert updated.reader_roles == ["finance_reader"]


def test_corpus_grant_disable_expected_version_prevents_stale_write() -> None:
    registry = CorpusGrantRegistry()
    created = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="alice",
    )

    with pytest.raises(CorpusGrantVersionConflictError, match="expected 0, current 1"):
        registry.disable(
            tenant_id="tenant-a",
            request=CorpusGrantDisableRequest(corpus_id="hr", expected_version=0),
            disabled_by="bob",
        )

    assert registry.get(tenant_id="tenant-a", corpus_id="hr") is not None
    disabled = registry.disable(
        tenant_id="tenant-a",
        request=CorpusGrantDisableRequest(corpus_id="hr", expected_version=created.version),
        disabled_by="bob",
    )
    repeated = registry.disable(
        tenant_id="tenant-a",
        request=CorpusGrantDisableRequest(corpus_id="hr", expected_version=disabled.version),
        disabled_by="carol",
    )

    assert disabled.version == 2
    assert repeated == disabled


def test_corpus_grant_list_paginates_after_filtering() -> None:
    registry = CorpusGrantRegistry()
    for corpus_id in ("alpha", "beta", "gamma"):
        registry.upsert(
            tenant_id="tenant-a",
            request=CorpusGrantUpsertRequest(corpus_id=corpus_id),
            updated_by="admin",
        )
    registry.upsert(
        tenant_id="tenant-b",
        request=CorpusGrantUpsertRequest(corpus_id="delta"),
        updated_by="admin",
    )

    first_page = registry.list_for_tenant("tenant-a", CorpusGrantListRequest(limit=2))
    second_page = registry.list_for_tenant(
        "tenant-a",
        CorpusGrantListRequest(limit=2, cursor=first_page.next_cursor),
    )

    assert [grant.corpus_id for grant in first_page.grants] == ["alpha", "beta"]
    assert first_page.next_cursor == "2"
    assert [grant.corpus_id for grant in second_page.grants] == ["gamma"]
    assert second_page.next_cursor is None


def test_corpus_grant_history_paginates_after_filtering_in_append_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CorpusGrantRegistry()
    timestamps = iter(
        datetime(2026, 7, 8, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
        for minute in range(5)
    )
    monkeypatch.setattr(registry, "_now", lambda: next(timestamps))
    first_hr = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="alice",
    )
    finance = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="finance", reader_roles=["finance_reader"]),
        updated_by="alice",
    )
    second_hr = registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["senior_hr_reader"]),
        updated_by="bob",
    )
    registry.upsert(
        tenant_id="tenant-b",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["tenant_b_reader"]),
        updated_by="mallory",
    )
    disabled = registry.disable(
        tenant_id="tenant-a",
        request=CorpusGrantDisableRequest(corpus_id="hr"),
        disabled_by="carol",
    )

    first_page = registry.history_for_tenant(
        "tenant-a",
        CorpusGrantHistoryRequest(corpus_id="hr", limit=1),
    )
    second_page = registry.history_for_tenant(
        "tenant-a",
        CorpusGrantHistoryRequest(corpus_id="hr", limit=10, cursor=first_page.next_cursor),
    )

    assert [grant.version for grant in first_page.grants] == [1]
    assert first_page.next_cursor == "1"
    assert [grant.version for grant in second_page.grants] == [2, 3]
    assert second_page.grants[-1].disabled_by == "carol"
    assert second_page.next_cursor is None

    bob_page = registry.history_for_tenant(
        "tenant-a",
        CorpusGrantHistoryRequest(corpus_id="hr", actor_id="bob"),
    )
    window_page = registry.history_for_tenant(
        "tenant-a",
        CorpusGrantHistoryRequest(
            updated_at_from=finance.updated_at,
            updated_at_to=disabled.updated_at,
        ),
    )

    assert bob_page.grants == [second_hr]
    assert first_hr not in window_page.grants
    assert [grant.corpus_id for grant in window_page.grants] == ["finance", "hr", "hr"]

    hr_diffs = registry.history_diffs_for_tenant(
        "tenant-a",
        CorpusGrantHistoryDiffRequest(corpus_id="hr"),
    )
    bob_diffs = registry.history_diffs_for_tenant(
        "tenant-a",
        CorpusGrantHistoryDiffRequest(corpus_id="hr", actor_id="bob"),
    )
    window_diffs = registry.history_diffs_for_tenant(
        "tenant-a",
        CorpusGrantHistoryDiffRequest(
            updated_at_from=finance.updated_at,
            updated_at_to=disabled.updated_at,
        ),
    )

    assert [diff.action for diff in hr_diffs.diffs] == ["create", "update", "disable"]
    assert [diff.previous_version for diff in hr_diffs.diffs] == [None, 1, 2]
    assert hr_diffs.diffs[-1].changed_fields == ["disabled_state"]
    assert bob_diffs.diffs[0].version == second_hr.version
    assert bob_diffs.diffs[0].previous_version == first_hr.version
    assert bob_diffs.diffs[0].reader_roles_added == ["senior_hr_reader"]
    assert bob_diffs.diffs[0].reader_roles_removed == ["hr_reader"]
    assert [diff.action for diff in window_diffs.diffs] == ["create", "update", "disable"]
    assert [diff.corpus_id for diff in window_diffs.diffs] == ["finance", "hr", "hr"]


def test_corpus_grant_registry_fails_closed_on_corrupt_record(tmp_path: Path) -> None:
    storage_path = tmp_path / "corpus-grants.jsonl"
    storage_path.write_text(
        json.dumps({"record_type": "unexpected", "payload": {}}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CorpusGrantStorageError, match="unsupported record_type"):
        CorpusGrantRegistry(storage_path=storage_path)


def test_create_corpus_grant_registry_rejects_memory_backend_in_production(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        environment="production",
        corpus_grants_backend="memory",
    )

    with pytest.raises(CorpusGrantConfigurationError, match="persistent corpus grants backend"):
        create_corpus_grant_registry(settings)


def test_create_corpus_grant_registry_accepts_jsonl_backend_in_production(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        environment="production",
        corpus_grants_backend="jsonl",
        corpus_grants_path=tmp_path / "grants.jsonl",
    )

    registry = create_corpus_grant_registry(settings)
    registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="admin",
    )

    assert registry.list_for_tenant("tenant-a", CorpusGrantListRequest()).grants[0].corpus_id == "hr"


def test_create_corpus_grant_registry_accepts_postgres_backend_with_injected_connection(
    tmp_path: Path,
) -> None:
    connection = RecordingCorpusGrantSqlConnection()
    settings = _settings(
        tmp_path,
        environment="production",
        corpus_grants_backend="postgres",
    )

    registry = create_corpus_grant_registry(settings, postgres_connection=connection)
    registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="admin",
    )

    assert connection.fetch_all_calls[0][0] == "SELECT payload FROM rag_corpus_grants ORDER BY sequence_id ASC"
    assert connection.execute_calls[0][1][0] == "tenant-a"
    assert registry.list_for_tenant("tenant-a", CorpusGrantListRequest()).grants[0].corpus_id == "hr"


def test_create_corpus_grant_registry_accepts_postgres_backend_with_runtime_dsn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_connections: list[RecordingCorpusGrantSqlConnection] = []

    class RecordingRuntimeConnection(RecordingCorpusGrantSqlConnection):
        def __init__(self, *, dsn: str) -> None:
            super().__init__()
            self.dsn = dsn
            created_connections.append(self)

    monkeypatch.setattr(
        corpus_grants_module,
        "PsycopgCorpusGrantSqlConnection",
        RecordingRuntimeConnection,
    )
    settings = _settings(
        tmp_path,
        environment="production",
        corpus_grants_backend="postgres",
        postgres_dsn="postgresql://postgres@localhost/hallu_defense",
    )

    registry = create_corpus_grant_registry(settings)
    registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="admin",
    )

    assert created_connections[0].dsn == "postgresql://postgres@localhost/hallu_defense"
    assert created_connections[0].fetch_all_calls[0][0] == (
        "SELECT payload FROM rag_corpus_grants ORDER BY sequence_id ASC"
    )
    assert created_connections[0].execute_calls[0][1][0] == "tenant-a"


def test_create_corpus_grant_registry_rejects_postgres_backend_without_connection(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        environment="production",
        corpus_grants_backend="postgres",
    )

    with pytest.raises(CorpusGrantConfigurationError, match="injected"):
        create_corpus_grant_registry(settings)


def test_registry_grant_enforces_writer_role_on_ingestion() -> None:
    registry = CorpusGrantRegistry()
    registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", writer_roles=["hr_writer"]),
        updated_by="admin",
    )
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(
        HybridRetriever(index_backend=backend),
        access_policy=RagAccessPolicy(corpus_grant_registry=registry),
    )
    request = DocumentIngestionRequest(
        corpus_id="hr",
        documents=[
            DocumentInput(
                source_ref="hr-manual",
                content="Remote work requests need manager approval.",
                authority=Authority.INTERNAL,
            )
        ],
    )

    with pytest.raises(RagAccessDeniedError, match="grant registry"):
        ingestor.ingest(request, tenant_id="tenant-a", trace_id="tr_grant_writer_denied")

    assert backend.indexed_chunks == []

    response = ingestor.ingest(
        request,
        tenant_id="tenant-a",
        trace_id="tr_grant_writer_allowed",
        principal_roles=frozenset({"hr_writer"}),
    )

    assert response.indexed_count == 1
    assert backend.indexed_chunks[0].metadata["corpus_id"] == "hr"
    assert backend.indexed_chunks[0].metadata["owner_tenant_id"] == "tenant-a"


def test_disabled_registry_grant_does_not_enforce_writer_role_on_ingestion() -> None:
    registry = CorpusGrantRegistry()
    registry.upsert(
        tenant_id="tenant-a",
        request=CorpusGrantUpsertRequest(corpus_id="hr", writer_roles=["hr_writer"]),
        updated_by="admin",
    )
    registry.disable(
        tenant_id="tenant-a",
        request=CorpusGrantDisableRequest(corpus_id="hr"),
        disabled_by="admin",
    )
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(
        HybridRetriever(index_backend=backend),
        access_policy=RagAccessPolicy(corpus_grant_registry=registry),
    )

    response = ingestor.ingest(
        DocumentIngestionRequest(
            corpus_id="hr",
            documents=[
                DocumentInput(
                    source_ref="hr-manual",
                    content="Remote work requests need manager approval.",
                    authority=Authority.INTERNAL,
                )
            ],
        ),
        tenant_id="tenant-a",
        trace_id="tr_disabled_grant",
    )

    assert response.indexed_count == 1


def test_registry_grant_filters_persistent_evidence_without_reader_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CorpusGrantRegistry()
    registry.upsert(
        tenant_id="tenant-route",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="admin",
    )
    backend = RecordingRagIndexBackend(
        search_results=[
            Evidence(
                evidence_id="ev_hr",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="hr-manual",
                content="Remote work requests need manager approval.",
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
                structured_content={"metadata": {"corpus_id": "hr"}},
            )
        ]
    )
    monkeypatch.setattr(routes, "hybrid_retriever", HybridRetriever(index_backend=backend))
    monkeypatch.setattr(
        routes,
        "rag_access_policy",
        RagAccessPolicy(corpus_grant_registry=registry),
    )

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_registry_reader_filtered"},
        json=_retrieval_payload(),
    )

    assert response.status_code == 200
    assert response.json()["evidence"] == []
    assert response.json()["claim_evidence_map"] == {"clm_remote": []}


def test_registry_grant_allows_persistent_evidence_with_reader_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CorpusGrantRegistry()
    registry.upsert(
        tenant_id="tenant-route",
        request=CorpusGrantUpsertRequest(corpus_id="hr", reader_roles=["hr_reader"]),
        updated_by="admin",
    )
    backend = RecordingRagIndexBackend(
        search_results=[
            Evidence(
                evidence_id="ev_hr",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="hr-manual",
                content="Remote work requests need manager approval.",
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
                structured_content={"metadata": {"corpus_id": "hr"}},
            )
        ]
    )
    monkeypatch.setattr(routes, "hybrid_retriever", HybridRetriever(index_backend=backend))
    monkeypatch.setattr(
        routes,
        "rag_access_policy",
        RagAccessPolicy(corpus_grant_registry=registry),
    )

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={
            "x-tenant-id": "tenant-route",
            "x-trace-id": "tr_registry_reader_allowed",
            "x-subject-id": "verifier",
            "x-roles": "hr_reader",
        },
        json=_retrieval_payload(),
    )

    assert response.status_code == 200
    assert [item["evidence_id"] for item in response.json()["evidence"]] == ["ev_hr"]
    assert response.json()["claim_evidence_map"] == {"clm_remote": ["ev_hr"]}


def test_corpus_grant_routes_upsert_list_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CorpusGrantRegistry()
    monkeypatch.setattr(routes, "corpus_grant_registry", registry)
    monkeypatch.setattr(
        routes,
        "rag_access_policy",
        RagAccessPolicy(corpus_grant_registry=registry),
    )

    client = TestClient(app)
    headers = {
        "x-tenant-id": "tenant-corpus-route",
        "x-trace-id": "tr_corpus_grant_route",
        "x-subject-id": "rag-admin",
        "x-roles": "rag_writer",
    }
    upsert_response = client.post(
        "/rag/corpus-grants/upsert",
        headers=headers,
        json={
            "corpus_id": "hr",
            "reader_roles": ["hr_reader"],
            "writer_roles": ["hr_writer"],
        },
    )
    list_response = client.post(
        "/rag/corpus-grants/list",
        headers={**headers, "x-trace-id": "tr_corpus_grant_list"},
        json={"limit": 10},
    )
    disable_response = client.post(
        "/rag/corpus-grants/disable",
        headers={**headers, "x-trace-id": "tr_corpus_grant_disable"},
        json={"corpus_id": "hr"},
    )
    active_list_response = client.post(
        "/rag/corpus-grants/list",
        headers={**headers, "x-trace-id": "tr_corpus_grant_active_list"},
        json={},
    )
    disabled_list_response = client.post(
        "/rag/corpus-grants/list",
        headers={**headers, "x-trace-id": "tr_corpus_grant_disabled_list"},
        json={"include_disabled": True},
    )
    history_response = client.post(
        "/rag/corpus-grants/history",
        headers={**headers, "x-trace-id": "tr_corpus_grant_history"},
        json={"corpus_id": "hr"},
    )
    diff_response = client.post(
        "/rag/corpus-grants/history/diff",
        headers={**headers, "x-trace-id": "tr_corpus_grant_history_diff"},
        json={"corpus_id": "hr"},
    )
    audit_response = client.post(
        "/audit/export",
        headers={"x-tenant-id": "tenant-corpus-route", "x-trace-id": "tr_corpus_grant_audit"},
        json={"include_events": True},
    )

    assert upsert_response.status_code == 200
    grant = upsert_response.json()["grant"]
    assert grant["tenant_id"] == "tenant-corpus-route"
    assert grant["corpus_id"] == "hr"
    assert grant["reader_roles"] == ["hr_reader"]
    assert grant["writer_roles"] == ["hr_writer"]
    assert grant["created_by"] == "rag-admin"
    assert grant["updated_by"] == "rag-admin"
    assert grant["version"] == 1
    assert grant["disabled_at"] is None
    assert list_response.status_code == 200
    assert list_response.json()["grants"][0]["corpus_id"] == "hr"
    assert list_response.json()["next_cursor"] is None
    assert disable_response.status_code == 200
    assert disable_response.json()["grant"]["disabled_by"] == "rag-admin"
    assert disable_response.json()["grant"]["version"] == 2
    assert active_list_response.status_code == 200
    assert active_list_response.json()["grants"] == []
    assert disabled_list_response.status_code == 200
    assert disabled_list_response.json()["grants"][0]["disabled_by"] == "rag-admin"
    assert history_response.status_code == 200
    assert [grant["version"] for grant in history_response.json()["grants"]] == [1, 2]
    assert history_response.json()["next_cursor"] is None
    assert diff_response.status_code == 200
    assert [diff["action"] for diff in diff_response.json()["diffs"]] == ["create", "disable"]
    assert diff_response.json()["diffs"][1]["previous_version"] == 1
    assert diff_response.json()["diffs"][1]["changed_fields"] == ["disabled_state"]
    assert diff_response.json()["next_cursor"] is None
    assert audit_response.status_code == 200
    assert any(
        event["event_type"] == "corpus_grant_upsert"
        and event["path"] == "/rag/corpus-grants/upsert"
        and event["metadata"]["corpus_id"] == "hr"
        for event in audit_response.json()["events"]
    )
    assert any(
        event["event_type"] == "corpus_grant_disable"
        and event["path"] == "/rag/corpus-grants/disable"
        and event["metadata"]["corpus_id"] == "hr"
        and event["metadata"]["version"] == 2
        for event in audit_response.json()["events"]
    )


def test_corpus_grant_upsert_route_requires_rag_writer_even_when_auth_optional() -> None:
    response = TestClient(app).post(
        "/rag/corpus-grants/upsert",
        headers={"x-tenant-id": "tenant-corpus-denied", "x-trace-id": "tr_corpus_grant_denied"},
        json={"corpus_id": "hr", "reader_roles": ["hr_reader"]},
    )

    assert response.status_code == 403
    assert "Authenticated principal is required" in response.json()["message"]


def test_corpus_grant_disable_route_returns_not_found_for_missing_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(routes, "corpus_grant_registry", CorpusGrantRegistry())

    response = TestClient(app).post(
        "/rag/corpus-grants/disable",
        headers={
            "x-tenant-id": "tenant-corpus-missing",
            "x-trace-id": "tr_corpus_grant_missing",
            "x-subject-id": "rag-admin",
            "x-roles": "rag_writer",
        },
        json={"corpus_id": "missing"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["message"]


def test_corpus_grant_routes_return_conflict_for_stale_expected_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CorpusGrantRegistry()
    monkeypatch.setattr(routes, "corpus_grant_registry", registry)
    client = TestClient(app)
    headers = {
        "x-tenant-id": "tenant-corpus-conflict",
        "x-trace-id": "tr_corpus_grant_conflict",
        "x-subject-id": "rag-admin",
        "x-roles": "rag_writer",
    }

    created_response = client.post(
        "/rag/corpus-grants/upsert",
        headers=headers,
        json={"corpus_id": "hr", "reader_roles": ["hr_reader"], "expected_version": 0},
    )
    stale_upsert_response = client.post(
        "/rag/corpus-grants/upsert",
        headers={**headers, "x-trace-id": "tr_corpus_grant_upsert_conflict"},
        json={"corpus_id": "hr", "reader_roles": ["finance_reader"], "expected_version": 0},
    )
    stale_disable_response = client.post(
        "/rag/corpus-grants/disable",
        headers={**headers, "x-trace-id": "tr_corpus_grant_disable_conflict"},
        json={"corpus_id": "hr", "expected_version": 0},
    )

    assert created_response.status_code == 200
    assert stale_upsert_response.status_code == 409
    assert "version conflict" in stale_upsert_response.json()["message"]
    assert stale_disable_response.status_code == 409
    assert "version conflict" in stale_disable_response.json()["message"]
    assert registry.get(tenant_id="tenant-corpus-conflict", corpus_id="hr") is not None


def test_corpus_grant_list_rejects_invalid_cursor() -> None:
    response = TestClient(app).post(
        "/rag/corpus-grants/list",
        headers={
            "x-tenant-id": "tenant-corpus-cursor",
            "x-trace-id": "tr_corpus_grant_bad_cursor",
            "x-subject-id": "verifier",
            "x-roles": "verifier",
        },
        json={"cursor": "not-an-offset"},
    )

    assert response.status_code == 400
    assert "cursor" in response.json()["message"]


def test_corpus_grant_history_rejects_invalid_cursor() -> None:
    response = TestClient(app).post(
        "/rag/corpus-grants/history",
        headers={
            "x-tenant-id": "tenant-corpus-history-cursor",
            "x-trace-id": "tr_corpus_grant_history_bad_cursor",
            "x-subject-id": "verifier",
            "x-roles": "verifier",
        },
        json={"cursor": "not-an-offset"},
    )

    assert response.status_code == 400
    assert "cursor" in response.json()["message"]


def test_corpus_grant_history_diff_rejects_invalid_cursor() -> None:
    response = TestClient(app).post(
        "/rag/corpus-grants/history/diff",
        headers={
            "x-tenant-id": "tenant-corpus-history-diff-cursor",
            "x-trace-id": "tr_corpus_grant_history_diff_bad_cursor",
            "x-subject-id": "verifier",
            "x-roles": "verifier",
        },
        json={"cursor": "not-an-offset"},
    )

    assert response.status_code == 400
    assert "cursor" in response.json()["message"]


def test_corpus_grant_history_rejects_inverted_time_range() -> None:
    response = TestClient(app).post(
        "/rag/corpus-grants/history",
        headers={
            "x-tenant-id": "tenant-corpus-history-range",
            "x-trace-id": "tr_corpus_grant_history_bad_range",
            "x-subject-id": "verifier",
            "x-roles": "verifier",
        },
        json={
            "updated_at_from": "2026-07-08T00:05:00Z",
            "updated_at_to": "2026-07-08T00:00:00Z",
        },
    )

    assert response.status_code == 400
    assert "updated_at_from" in response.json()["message"]


class RecordingCorpusGrantSqlConnection:
    def __init__(self, rows: Sequence[Mapping[str, object]] = ()) -> None:
        self.execute_calls: list[tuple[str, Sequence[object]]] = []
        self.fetch_all_calls: list[tuple[str, Sequence[object]]] = []
        self._rows = list(rows)

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        self.execute_calls.append((statement, parameters))

    def fetch_all(
        self,
        statement: str,
        parameters: Sequence[object],
    ) -> Sequence[Mapping[str, object]]:
        self.fetch_all_calls.append((statement, parameters))
        return self._rows


class RecordingPsycopgCursor:
    def __init__(self, rows: Sequence[Mapping[str, object]]) -> None:
        self.execute_calls: list[tuple[str, Sequence[object]]] = []
        self._rows = list(rows)

    def __enter__(self) -> "RecordingPsycopgCursor":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        return None

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        self.execute_calls.append((statement, parameters))

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        return self._rows


class RecordingPsycopgConnection:
    def __init__(self, rows: Sequence[Mapping[str, object]]) -> None:
        self.cursor_instance = RecordingPsycopgCursor(rows)

    def __enter__(self) -> "RecordingPsycopgConnection":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        return None

    def cursor(self) -> RecordingPsycopgCursor:
        return self.cursor_instance


class RecordingPsycopgConnect:
    def __init__(self, rows: Sequence[Mapping[str, object]]) -> None:
        self.calls: list[tuple[str, object | None]] = []
        self.connections: list[RecordingPsycopgConnection] = []
        self._rows = list(rows)

    def __call__(
        self,
        conninfo: str,
        *,
        row_factory: object | None = None,
    ) -> RecordingPsycopgConnection:
        self.calls.append((conninfo, row_factory))
        connection = RecordingPsycopgConnection(self._rows)
        self.connections.append(connection)
        return connection


class RecordingRagIndexBackend:
    backend_name = "recording"

    def __init__(self, search_results: Sequence[Evidence] = ()) -> None:
        self.indexed_chunks: list[RagChunk] = []
        self.search_requests: list[RagSearchRequest] = []
        self._search_results = list(search_results)

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        self.indexed_chunks.extend(chunks)
        return RagIndexWriteResult(
            indexed_count=len(chunks),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in chunks],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        self.search_requests.append(search_request)
        return list(self._search_results)


def _retrieval_payload() -> dict[str, object]:
    return {
        "claims": [
            Claim(
                claim_id="clm_remote",
                text="Remote work requests need manager approval.",
                type=ClaimType.DOC_GROUNDED,
                risk_level=RiskLevel.MEDIUM,
            ).model_dump(mode="json")
        ],
        "context_refs": ["hr-manual"],
        "max_evidence_per_claim": 2,
    }


def _settings(
    tmp_path: Path,
    *,
    environment: str,
    corpus_grants_backend: str,
    corpus_grants_path: Path | None = None,
    postgres_dsn: str | None = None,
) -> Settings:
    return Settings(
        environment=environment,
        policy_version="test",
        auth_required=environment in {"production", "staging"},
        allowed_workspace=tmp_path,
        max_command_seconds=5,
        max_output_chars=1000,
        auth_claims_mode=(
            "signed_headers" if environment in {"production", "staging"} else "unsigned_headers"
        ),
        corpus_grants_backend=corpus_grants_backend,
        corpus_grants_path=corpus_grants_path or (tmp_path / "corpus-grants.jsonl"),
        postgres_dsn=postgres_dsn,
    )
