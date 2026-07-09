from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hallu_defense.config import Settings
from hallu_defense.api import routes
from hallu_defense.domain.models import (
    Authority,
    Claim,
    ClaimType,
    DocumentIngestionRequest,
    DocumentInput,
    Evidence,
    EvidenceKind,
    Freshness,
    RiskLevel,
    StalenessClass,
)
from hallu_defense.main import app
from hallu_defense.services.ingestion import DocumentIngestionService
from hallu_defense.services.rag_access import RagAccessDeniedError
from hallu_defense.services.rag_index import (
    DeterministicHashEmbedder,
    OpenSearchRagIndexBackend,
    PgVectorRagIndexBackend,
    PsycopgPgVectorConnection,
    RagChunk,
    RagIndexConfigurationError,
    RagIndexTransportError,
    RagIndexWriteResult,
    RagSearchRequest,
    create_rag_index_backend,
)
import hallu_defense.services.rag_index as rag_index_module
from hallu_defense.services.retrieval import HybridRetriever


def test_hybrid_retriever_indexes_documents_as_tenant_scoped_chunks() -> None:
    backend = RecordingRagIndexBackend()
    retriever = HybridRetriever(index_backend=backend)

    result = retriever.index_documents(
        tenant_id="tenant-a",
        documents=[
            DocumentInput(
                source_ref="policy",
                content="First paragraph.\n\nSecond paragraph.",
                authority=Authority.INTERNAL,
                metadata={"department": "hr", "staleness_class": "fresh"},
            )
        ],
    )

    assert result.indexed_count == 2
    assert result.backend == "recording"
    assert len(result.evidence_ids) == 2
    assert all(evidence_id.startswith("ev_") for evidence_id in result.evidence_ids)
    assert result.evidence_ids[0] != result.evidence_ids[1]
    assert [chunk.tenant_id for chunk in backend.indexed_chunks] == ["tenant-a", "tenant-a"]
    assert [chunk.evidence_id for chunk in backend.indexed_chunks] == result.evidence_ids
    assert backend.indexed_chunks[0].metadata["department"] == "hr"
    assert backend.indexed_chunks[0].document_index == 1
    assert backend.indexed_chunks[1].chunk_index == 2


def test_hybrid_retriever_persistent_evidence_ids_are_stable_and_source_scoped() -> None:
    first_backend = RecordingRagIndexBackend()
    second_backend = RecordingRagIndexBackend()
    first_retriever = HybridRetriever(index_backend=first_backend)
    second_retriever = HybridRetriever(index_backend=second_backend)

    first_retriever.index_documents(
        tenant_id="tenant-a",
        documents=[
            DocumentInput(
                source_ref="policy-a",
                content="First paragraph.\n\nSecond paragraph.",
                metadata={"corpus_id": "hr"},
            ),
            DocumentInput(
                source_ref="policy-b",
                content="First paragraph.",
                metadata={"corpus_id": "hr"},
            ),
        ],
    )
    second_retriever.index_documents(
        tenant_id="tenant-a",
        documents=[
            DocumentInput(
                source_ref="policy-a",
                content="Updated first paragraph.\n\nUpdated second paragraph.",
                metadata={"corpus_id": "hr"},
            )
        ],
    )

    assert first_backend.indexed_chunks[0].evidence_id == second_backend.indexed_chunks[0].evidence_id
    assert first_backend.indexed_chunks[1].evidence_id != second_backend.indexed_chunks[0].evidence_id
    assert first_backend.indexed_chunks[2].evidence_id != second_backend.indexed_chunks[0].evidence_id


def test_hybrid_retriever_indexes_markdown_sections_with_structure_metadata() -> None:
    backend = RecordingRagIndexBackend()
    retriever = HybridRetriever(index_backend=backend)

    result = retriever.index_documents(
        tenant_id="tenant-a",
        documents=[
            DocumentInput(
                source_ref="policy",
                content=(
                    "# Remote policy\n"
                    "Remote work requests must be approved by a manager.\n\n"
                    "## Device security\n"
                    "Managed devices must use disk encryption."
                ),
                authority=Authority.INTERNAL,
                metadata={"department": "hr"},
            )
        ],
    )

    assert result.indexed_count == 2
    assert [chunk.content for chunk in backend.indexed_chunks] == [
        "Remote policy\n\nRemote work requests must be approved by a manager.",
        "Device security\n\nManaged devices must use disk encryption.",
    ]
    assert backend.indexed_chunks[0].metadata == {
        "department": "hr",
        "structural_section_heading": "Remote policy",
        "structural_section_path": "Remote policy",
        "structural_section_level": 1,
        "structural_chunk_kind": "section",
    }
    assert backend.indexed_chunks[1].metadata["structural_section_path"] == (
        "Remote policy > Device security"
    )
    assert backend.indexed_chunks[1].metadata["structural_section_level"] == 2


def test_hybrid_retriever_queries_persistent_backend_with_tenant_filters_and_context_refs() -> None:
    backend = RecordingRagIndexBackend(
        search_results=[
            Evidence(
                evidence_id="ev_persistent",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="persisted-policy",
                content="Remote work requests must be approved by a manager.",
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
                structured_content={"retrieval": {"ranker": "recording"}},
            )
        ]
    )
    retriever = HybridRetriever(index_backend=backend)
    claim = Claim(
        claim_id="clm_remote",
        text="Remote work requests must be approved by a manager.",
        type=ClaimType.DOC_GROUNDED,
        risk_level=RiskLevel.MEDIUM,
    )

    evidence, claim_map = retriever.retrieve(
        [claim],
        [],
        metadata_filter={"department": "hr"},
        tenant_id="tenant-a",
        context_refs=["persisted-policy"],
    )

    assert [item.evidence_id for item in evidence] == ["ev_persistent"]
    assert claim_map == {"clm_remote": ["ev_persistent"]}
    assert backend.search_requests[0].tenant_id == "tenant-a"
    assert backend.search_requests[0].metadata_filter == {"department": "hr"}
    assert backend.search_requests[0].context_refs == ["persisted-policy"]


def test_hybrid_retriever_requires_tenant_for_persistent_backend() -> None:
    retriever = HybridRetriever(index_backend=RecordingRagIndexBackend())
    claim = Claim(claim_id="clm", text="A policy exists.")

    with pytest.raises(ValueError, match="tenant_id"):
        retriever.retrieve([claim], [])


def test_hybrid_retriever_returns_inline_section_structure() -> None:
    retriever = HybridRetriever()
    claim = Claim(
        claim_id="clm_devices",
        text="Managed devices must use disk encryption.",
        type=ClaimType.DOC_GROUNDED,
        risk_level=RiskLevel.MEDIUM,
    )

    evidence, claim_map = retriever.retrieve(
        [claim],
        [
            DocumentInput(
                source_ref="security-policy",
                content=(
                    "# Remote policy\n"
                    "Remote work requests must be approved by a manager.\n\n"
                    "## Device security\n"
                    "Managed devices must use disk encryption."
                ),
                authority=Authority.INTERNAL,
                metadata={"department": "security"},
            )
        ],
        max_evidence_per_claim=1,
    )

    assert claim_map == {"clm_devices": ["ev_001_002"]}
    assert len(evidence) == 1
    assert evidence[0].structured_content["structure"] == {
        "section_heading": "Device security",
        "section_path": ["Remote policy", "Device security"],
        "section_level": 2,
        "chunk_kind": "section",
    }
    assert evidence[0].structured_content["metadata"]["structural_section_path"] == (
        "Remote policy > Device security"
    )


def test_document_ingestion_service_adds_corpus_metadata_and_reports_indexed_ids() -> None:
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))

    response = ingestor.ingest(
        DocumentIngestionRequest(
            corpus_id="hr",
            documents=[
                DocumentInput(
                    source_ref="policy-a",
                    content="Remote work requests must be approved by a manager.",
                    authority=Authority.INTERNAL,
                    metadata={"department": "hr"},
                )
            ],
        ),
        tenant_id="tenant-a",
        trace_id="tr_ingest",
    )

    assert response.trace_id == "tr_ingest"
    assert response.tenant_id == "tenant-a"
    assert response.corpus_id == "hr"
    assert response.backend == "recording"
    assert response.document_count == 1
    assert response.indexed_count == 1
    assert len(response.evidence_ids) == 1
    assert response.evidence_ids[0].startswith("ev_")
    assert response.warnings == []
    assert backend.indexed_chunks[0].metadata == {
        "department": "hr",
        "corpus_id": "hr",
        "owner_tenant_id": "tenant-a",
    }


def test_document_ingestion_service_rejects_cross_tenant_owner_metadata() -> None:
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))

    with pytest.raises(RagAccessDeniedError, match="owner_tenant_id"):
        ingestor.ingest(
            DocumentIngestionRequest(
                corpus_id="hr",
                documents=[
                    DocumentInput(
                        source_ref="policy-a",
                        content="Remote work requests must be approved by a manager.",
                        authority=Authority.INTERNAL,
                        metadata={"owner_tenant_id": "tenant-b"},
                    )
                ],
            ),
            tenant_id="tenant-a",
            trace_id="tr_cross_tenant_ingest",
        )

    assert backend.indexed_chunks == []


def test_document_ingestion_service_rejects_conflicting_corpus_metadata() -> None:
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))

    with pytest.raises(RagAccessDeniedError, match="corpus_id"):
        ingestor.ingest(
            DocumentIngestionRequest(
                corpus_id="hr",
                documents=[
                    DocumentInput(
                        source_ref="policy-a",
                        content="Remote work requests must be approved by a manager.",
                        authority=Authority.INTERNAL,
                        metadata={"corpus_id": "finance"},
                    )
                ],
            ),
            tenant_id="tenant-a",
            trace_id="tr_conflicting_corpus",
        )

    assert backend.indexed_chunks == []


def test_document_ingestion_service_rejects_missing_corpus_writer_role() -> None:
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))

    with pytest.raises(RagAccessDeniedError, match="writer role"):
        ingestor.ingest(
            DocumentIngestionRequest(
                corpus_id="hr",
                documents=[
                    DocumentInput(
                        source_ref="policy-a",
                        content="Remote work requests must be approved by a manager.",
                        authority=Authority.INTERNAL,
                        metadata={"corpus_writer_roles": ["hr_corpus_writer"]},
                    )
                ],
            ),
            tenant_id="tenant-a",
            trace_id="tr_writer_role_denied",
        )

    assert backend.indexed_chunks == []


def test_document_ingestion_service_allows_matching_corpus_writer_role() -> None:
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))

    response = ingestor.ingest(
        DocumentIngestionRequest(
            corpus_id="hr",
            documents=[
                DocumentInput(
                    source_ref="policy-a",
                    content="Remote work requests must be approved by a manager.",
                    authority=Authority.INTERNAL,
                    metadata={"corpus_writer_roles": ["hr_corpus_writer"]},
                )
            ],
        ),
        tenant_id="tenant-a",
        trace_id="tr_writer_role_allowed",
        principal_roles=frozenset({"hr_corpus_writer"}),
    )

    assert response.indexed_count == 1
    assert backend.indexed_chunks[0].metadata["corpus_writer_roles"] == ["hr_corpus_writer"]


def test_document_ingestion_service_warns_when_backend_is_local() -> None:
    ingestor = DocumentIngestionService(HybridRetriever())

    response = ingestor.ingest(
        DocumentIngestionRequest(
            documents=[
                DocumentInput(
                    source_ref="policy-a",
                    content="Remote work requests must be approved by a manager.",
                    authority=Authority.INTERNAL,
                )
            ],
        ),
        tenant_id="tenant-a",
        trace_id="tr_local_ingest",
    )

    assert response.backend == "local"
    assert response.indexed_count == 0
    assert response.evidence_ids == []
    assert response.warnings == [
        "No persistent RAG index backend is configured; documents were validated but not persisted."
    ]


def test_document_ingestion_endpoint_uses_request_tenant_and_trace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend()
    monkeypatch.setattr(
        routes,
        "document_ingestor",
        DocumentIngestionService(HybridRetriever(index_backend=backend)),
    )

    response = TestClient(app).post(
        "/documents/ingest",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_route_ingest"},
        json={
            "corpus_id": "hr",
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Remote work requests must be approved by a manager.",
                    "authority": "internal",
                    "metadata": {"department": "hr"},
                }
            ],
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["trace_id"] == "tr_route_ingest"
    assert payload["tenant_id"] == "tenant-route"
    assert payload["backend"] == "recording"
    assert len(payload["evidence_ids"]) == 1
    assert payload["evidence_ids"][0].startswith("ev_")
    assert backend.indexed_chunks[0].tenant_id == "tenant-route"
    assert backend.indexed_chunks[0].metadata["owner_tenant_id"] == "tenant-route"


def test_document_ingestion_endpoint_returns_503_when_persistent_backend_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        routes,
        "document_ingestor",
        DocumentIngestionService(HybridRetriever(index_backend=FailingRagIndexBackend())),
    )

    response = TestClient(app).post(
        "/documents/ingest",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_route_ingest_failed"},
        json={
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Remote work requests must be approved by a manager.",
                    "authority": "internal",
                }
            ],
        },
    )

    assert response.status_code == 503
    assert response.json()["message"] == "persistent backend unavailable"


def test_document_ingestion_endpoint_rejects_cross_tenant_owner_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend()
    monkeypatch.setattr(
        routes,
        "document_ingestor",
        DocumentIngestionService(HybridRetriever(index_backend=backend)),
    )

    response = TestClient(app).post(
        "/documents/ingest",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_route_ingest_denied"},
        json={
            "corpus_id": "hr",
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Remote work requests must be approved by a manager.",
                    "authority": "internal",
                    "metadata": {"owner_tenant_id": "tenant-other"},
                }
            ],
        },
    )

    assert response.status_code == 403
    assert "owner_tenant_id" in response.json()["message"]
    assert backend.indexed_chunks == []


def test_document_ingestion_endpoint_rejects_missing_corpus_writer_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend()
    monkeypatch.setattr(
        routes,
        "document_ingestor",
        DocumentIngestionService(HybridRetriever(index_backend=backend)),
    )

    response = TestClient(app).post(
        "/documents/ingest",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_writer_denied"},
        json={
            "corpus_id": "hr",
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Remote work requests must be approved by a manager.",
                    "authority": "internal",
                    "metadata": {"corpus_writer_roles": ["hr_corpus_writer"]},
                }
            ],
        },
    )

    assert response.status_code == 403
    assert "writer role" in response.json()["message"]
    assert backend.indexed_chunks == []


def test_document_ingestion_endpoint_allows_matching_corpus_writer_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend()
    monkeypatch.setattr(
        routes,
        "document_ingestor",
        DocumentIngestionService(HybridRetriever(index_backend=backend)),
    )

    response = TestClient(app).post(
        "/documents/ingest",
        headers={
            "x-tenant-id": "tenant-route",
            "x-trace-id": "tr_writer_allowed",
            "x-subject-id": "rag-writer",
            "x-roles": "hr_corpus_writer",
        },
        json={
            "corpus_id": "hr",
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Remote work requests must be approved by a manager.",
                    "authority": "internal",
                    "metadata": {"corpus_writer_roles": ["hr_corpus_writer"]},
                }
            ],
        },
    )

    assert response.status_code == 200
    assert backend.indexed_chunks[0].metadata["corpus_writer_roles"] == ["hr_corpus_writer"]


def test_retrieval_endpoint_passes_tenant_context_to_persistent_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend(
        search_results=[
            Evidence(
                evidence_id="ev_endpoint",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="persisted-policy",
                content="Remote work requests must be approved by a manager.",
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
            )
        ]
    )
    monkeypatch.setattr(routes, "hybrid_retriever", HybridRetriever(index_backend=backend))

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={"x-tenant-id": "tenant-route"},
        json={
            "claims": [
                {
                    "claim_id": "clm_remote",
                    "text": "Remote work requests must be approved by a manager.",
                    "canonical_form": "",
                    "type": "doc_grounded",
                    "risk_level": "medium",
                    "requires_evidence": True,
                    "metadata": {},
                }
            ],
            "context_refs": ["persisted-policy"],
            "metadata_filter": {"department": "hr"},
            "max_evidence_per_claim": 2,
        },
    )

    assert response.status_code == 200
    assert response.json()["claim_evidence_map"] == {"clm_remote": ["ev_endpoint"]}
    assert backend.search_requests[0].tenant_id == "tenant-route"
    assert backend.search_requests[0].context_refs == ["persisted-policy"]
    assert backend.search_requests[0].metadata_filter == {"department": "hr"}


def test_retrieval_endpoint_returns_503_when_persistent_backend_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        routes,
        "hybrid_retriever",
        HybridRetriever(index_backend=FailingRagIndexBackend()),
    )

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_route_retrieve_failed"},
        json={
            "claims": [
                {
                    "claim_id": "clm_remote",
                    "text": "Remote work requests must be approved by a manager.",
                    "canonical_form": "",
                    "type": "doc_grounded",
                    "risk_level": "medium",
                    "requires_evidence": True,
                    "metadata": {},
                }
            ],
            "max_evidence_per_claim": 2,
        },
    )

    assert response.status_code == 503
    assert response.json()["message"] == "persistent backend unavailable"


def test_retrieval_endpoint_rejects_cross_tenant_owner_metadata_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend()
    monkeypatch.setattr(routes, "hybrid_retriever", HybridRetriever(index_backend=backend))

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_route_retrieve_denied"},
        json={
            "claims": [
                {
                    "claim_id": "clm_remote",
                    "text": "Remote work requests must be approved by a manager.",
                    "canonical_form": "",
                    "type": "doc_grounded",
                    "risk_level": "medium",
                    "requires_evidence": True,
                    "metadata": {},
                }
            ],
            "metadata_filter": {"owner_tenant_id": ["tenant-route", "tenant-other"]},
            "max_evidence_per_claim": 2,
        },
    )

    assert response.status_code == 403
    assert "owner_tenant_id" in response.json()["message"]
    assert backend.search_requests == []


def test_retrieval_endpoint_rejects_restricted_inline_document_without_reader_role() -> None:
    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_reader_inline_denied"},
        json={
            "claims": [
                {
                    "claim_id": "clm_remote",
                    "text": "Remote work requests must be approved by a manager.",
                    "canonical_form": "",
                    "type": "doc_grounded",
                    "risk_level": "medium",
                    "requires_evidence": True,
                    "metadata": {},
                }
            ],
            "documents": [
                {
                    "source_ref": "policy-a",
                    "content": "Remote work requests must be approved by a manager.",
                    "authority": "internal",
                    "metadata": {"corpus_reader_roles": ["hr_corpus_reader"]},
                }
            ],
            "max_evidence_per_claim": 2,
        },
    )

    assert response.status_code == 403
    assert "reader role" in response.json()["message"]


def test_retrieval_endpoint_filters_persistent_evidence_without_reader_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend(
        search_results=[
            Evidence(
                evidence_id="ev_restricted",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="persisted-policy",
                content="Remote work requests must be approved by a manager.",
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
                structured_content={
                    "metadata": {"corpus_id": "hr", "corpus_reader_roles": ["hr_corpus_reader"]}
                },
            )
        ]
    )
    monkeypatch.setattr(routes, "hybrid_retriever", HybridRetriever(index_backend=backend))

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={"x-tenant-id": "tenant-route", "x-trace-id": "tr_reader_filtered"},
        json={
            "claims": [
                {
                    "claim_id": "clm_remote",
                    "text": "Remote work requests must be approved by a manager.",
                    "canonical_form": "",
                    "type": "doc_grounded",
                    "risk_level": "medium",
                    "requires_evidence": True,
                    "metadata": {},
                }
            ],
            "context_refs": ["persisted-policy"],
            "max_evidence_per_claim": 2,
        },
    )

    assert response.status_code == 200
    assert response.json()["evidence"] == []
    assert response.json()["claim_evidence_map"] == {"clm_remote": []}
    assert backend.search_requests[0].tenant_id == "tenant-route"


def test_retrieval_endpoint_allows_persistent_evidence_with_reader_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = RecordingRagIndexBackend(
        search_results=[
            Evidence(
                evidence_id="ev_restricted",
                kind=EvidenceKind.DOCUMENT_CHUNK,
                source_ref="persisted-policy",
                content="Remote work requests must be approved by a manager.",
                authority=Authority.INTERNAL,
                freshness=Freshness(staleness_class=StalenessClass.FRESH),
                structured_content={
                    "metadata": {"corpus_id": "hr", "corpus_reader_roles": ["hr_corpus_reader"]}
                },
            )
        ]
    )
    monkeypatch.setattr(routes, "hybrid_retriever", HybridRetriever(index_backend=backend))

    response = TestClient(app).post(
        "/evidence/retrieve",
        headers={
            "x-tenant-id": "tenant-route",
            "x-trace-id": "tr_reader_allowed",
            "x-subject-id": "verifier",
            "x-roles": "hr_corpus_reader",
        },
        json={
            "claims": [
                {
                    "claim_id": "clm_remote",
                    "text": "Remote work requests must be approved by a manager.",
                    "canonical_form": "",
                    "type": "doc_grounded",
                    "risk_level": "medium",
                    "requires_evidence": True,
                    "metadata": {},
                }
            ],
            "context_refs": ["persisted-policy"],
            "max_evidence_per_claim": 2,
        },
    )

    assert response.status_code == 200
    assert [item["evidence_id"] for item in response.json()["evidence"]] == ["ev_restricted"]
    assert response.json()["claim_evidence_map"] == {"clm_remote": ["ev_restricted"]}


def test_opensearch_index_bulk_payload_includes_tenant_metadata() -> None:
    transport = RecordingOpenSearchTransport()
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    result = backend.index_chunks([_chunk()])

    assert result.indexed_count == 1
    method, path, body, headers, timeout = transport.calls[0]
    assert method == "POST"
    assert path == "/_bulk"
    assert headers == {"content-type": "application/x-ndjson"}
    assert timeout == 3
    assert isinstance(body, list)
    assert body[0]["index"]["_index"] == "hallu_evidence"
    assert body[0]["index"]["_id"] != "ev_001_001"
    assert body[1]["tenant_id"] == "tenant-a"
    assert body[1]["evidence_id"] == "ev_001_001"
    assert body[1]["metadata"] == {"department": "hr"}


def test_opensearch_bulk_errors_fail_closed() -> None:
    transport = RecordingOpenSearchTransport(
        bulk_response={
            "errors": True,
            "items": [
                {
                    "index": {
                        "status": 201,
                    }
                },
                {
                    "index": {
                        "status": 400,
                        "error": {
                            "type": "mapper_parsing_exception",
                            "reason": "failed to parse field [metadata]",
                        },
                    }
                }
            ],
        }
    )
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    with pytest.raises(RagIndexTransportError, match="failed to parse field"):
        backend.index_chunks([_chunk()])


def test_opensearch_document_ids_are_tenant_scoped_to_prevent_cross_tenant_overwrite() -> None:
    transport = RecordingOpenSearchTransport()
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    backend.index_chunks([_chunk(tenant_id="tenant-a", evidence_id="ev_shared")])
    backend.index_chunks([_chunk(tenant_id="tenant-b", evidence_id="ev_shared")])

    first_body = transport.calls[0][2]
    second_body = transport.calls[1][2]
    assert isinstance(first_body, list)
    assert isinstance(second_body, list)
    first_document_id = first_body[0]["index"]["_id"]
    second_document_id = second_body[0]["index"]["_id"]
    assert first_document_id != second_document_id
    assert first_body[1]["tenant_id"] == "tenant-a"
    assert second_body[1]["tenant_id"] == "tenant-b"
    assert first_body[1]["evidence_id"] == "ev_shared"
    assert second_body[1]["evidence_id"] == "ev_shared"


def test_opensearch_search_filters_tenant_metadata_and_context_refs() -> None:
    transport = RecordingOpenSearchTransport(
        search_response={
            "hits": {
                "hits": [
                    {
                        "_score": 1.2,
                        "_source": {
                            "tenant_id": "tenant-a",
                            "evidence_id": "ev_a",
                            "source_ref": "policy-a",
                            "content": "Remote work needs manager approval.",
                            "authority": "internal",
                            "metadata": {
                                "department": "hr",
                                "structural_section_heading": "Remote policy",
                                "structural_section_path": "Handbook > Remote policy",
                                "structural_section_level": 2,
                                "structural_chunk_kind": "section",
                            },
                            "freshness": {"staleness_class": "fresh"},
                        },
                    },
                    {
                        "_score": 99,
                        "_source": {
                            "tenant_id": "tenant-b",
                            "evidence_id": "ev_b",
                            "source_ref": "policy-b",
                            "content": "Cross-tenant evidence must be ignored.",
                            "authority": "internal",
                            "metadata": {"department": "hr"},
                            "freshness": {"staleness_class": "fresh"},
                        },
                    },
                ]
            }
        }
    )
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    evidence = backend.search(
        RagSearchRequest(
            tenant_id="tenant-a",
            claim_id="clm_remote",
            query_text="Remote work needs manager approval.",
            metadata_filter={"department": "hr"},
            context_refs=["policy-a"],
            max_results=5,
        )
    )

    body = transport.calls[0][2]
    assert isinstance(body, dict)
    filters = body["query"]["bool"]["filter"]
    assert {"term": {"tenant_id": "tenant-a"}} in filters
    assert {"term": {"metadata.department": "hr"}} in filters
    assert {"terms": {"source_ref": ["policy-a"]}} in filters
    assert [item.evidence_id for item in evidence] == ["ev_a"]
    assert evidence[0].structured_content["retrieval"]["tenant_scoped"] is True
    assert evidence[0].structured_content["structure"] == {
        "section_heading": "Remote policy",
        "section_path": ["Handbook", "Remote policy"],
        "section_level": 2,
        "chunk_kind": "section",
    }


def test_opensearch_installs_index_template() -> None:
    transport = RecordingOpenSearchTransport()
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    result = backend.install_index_template(
        template_name="hallu_evidence_template",
        template=_opensearch_template(),
    )

    assert result.acknowledged is True
    assert result.path == "/_index_template/hallu_evidence_template"
    method, path, body, headers, timeout = transport.calls[0]
    assert method == "PUT"
    assert path == "/_index_template/hallu_evidence_template"
    assert headers is None
    assert timeout == 3
    assert isinstance(body, dict)
    assert body["index_patterns"] == ["hallu_evidence*"]
    assert body["_meta"]["required_query_filter"] == "tenant_id"


def test_opensearch_rejects_unsafe_index_names() -> None:
    with pytest.raises(RagIndexConfigurationError, match="identifier"):
        OpenSearchRagIndexBackend(
            endpoint="http://opensearch:9200",
            index_name="bad-index;drop",
            timeout_seconds=3,
            transport=RecordingOpenSearchTransport(),
        )


def test_opensearch_rejects_unsafe_template_names() -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=RecordingOpenSearchTransport(),
    )

    with pytest.raises(RagIndexConfigurationError, match="identifier"):
        backend.install_index_template(
            template_name="bad-template;drop",
            template=_opensearch_template(),
        )


def test_opensearch_rejects_invalid_template_payload() -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=RecordingOpenSearchTransport(),
    )

    with pytest.raises(RagIndexConfigurationError, match="index_patterns"):
        backend.install_index_template(
            template_name="hallu_evidence_template",
            template={"template": {"mappings": {}}},
        )


def test_pgvector_index_and_search_are_parameterized_and_tenant_scoped() -> None:
    connection = RecordingPgVectorConnection(
        rows=[
            {
                "tenant_id": "tenant-a",
                "evidence_id": "ev_pg",
                "source_ref": "policy-a",
                "content": "Remote work needs manager approval.",
                "authority": "internal",
                "staleness_class": "fresh",
                "published_at": None,
                "metadata": {"department": "hr"},
            }
        ]
    )
    backend = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks",
        connection=connection,
        embedder=DeterministicHashEmbedder(dimension=4),
    )

    backend.index_chunks([_chunk()])
    evidence = backend.search(
        RagSearchRequest(
            tenant_id="tenant-a",
            claim_id="clm_remote",
            query_text="Remote work needs manager approval.",
            metadata_filter={"department": "hr"},
            context_refs=["policy-a"],
            max_results=3,
        )
    )

    insert_statement, insert_parameters = connection.execute_many_calls[0]
    assert "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::vector)" in insert_statement
    assert insert_parameters[0][0] == "tenant-a"
    assert insert_parameters[0][1] == "ev_001_001"

    search_statement, search_parameters = connection.fetch_all_calls[0]
    assert "tenant_id = %s" in search_statement
    assert "source_ref = ANY(%s)" in search_statement
    assert "metadata @> %s::jsonb" in search_statement
    assert "ORDER BY embedding <=> %s::vector" in search_statement
    assert search_parameters[0] == "tenant-a"
    assert search_parameters[1] == ["policy-a"]
    assert search_parameters[2] == '{"department": "hr"}'
    assert search_parameters[-1] == 3
    assert [item.evidence_id for item in evidence] == ["ev_pg"]


def test_pgvector_rejects_unsafe_table_names() -> None:
    with pytest.raises(RagIndexConfigurationError, match="identifier"):
        PgVectorRagIndexBackend(
            table_name="rag_chunks;drop",
            connection=RecordingPgVectorConnection(),
        )


def test_create_pgvector_backend_uses_runtime_psycopg_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_connect = RecordingPgVectorPsycopgConnect(
        rows=[
            {
                "tenant_id": "tenant-a",
                "evidence_id": "ev_pg",
                "source_ref": "policy-a",
                "content": "Remote work needs manager approval.",
                "authority": "internal",
                "staleness_class": "fresh",
                "published_at": None,
                "metadata": {"department": "hr"},
            }
        ]
    )
    monkeypatch.setattr(
        rag_index_module,
        "_load_psycopg_connect",
        lambda: (fake_connect, "dict-row"),
    )
    backend = create_rag_index_backend(
        _settings(
            rag_index_backend="pgvector",
            postgres_dsn="postgresql://postgres@localhost/hallu_defense",
        )
    )

    assert isinstance(backend, PgVectorRagIndexBackend)

    backend.index_chunks([_chunk()])
    evidence = backend.search(
        RagSearchRequest(
            tenant_id="tenant-a",
            claim_id="clm_remote",
            query_text="Remote work needs manager approval.",
            metadata_filter={"department": "hr"},
            context_refs=["policy-a"],
            max_results=3,
        )
    )

    assert fake_connect.calls == [
        ("postgresql://postgres@localhost/hallu_defense", "dict-row"),
        ("postgresql://postgres@localhost/hallu_defense", "dict-row"),
    ]
    assert fake_connect.connections[0].cursor_instance.executemany_calls
    assert fake_connect.connections[1].cursor_instance.execute_calls
    assert [item.evidence_id for item in evidence] == ["ev_pg"]


def test_create_pgvector_backend_requires_postgres_dsn() -> None:
    with pytest.raises(RagIndexConfigurationError, match="HALLU_DEFENSE_POSTGRES_DSN"):
        create_rag_index_backend(_settings(rag_index_backend="pgvector", postgres_dsn=None))


def test_create_pgvector_backend_fails_closed_when_psycopg_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_import(module_name: str) -> object:
        raise ImportError(f"{module_name} unavailable")

    monkeypatch.setattr(rag_index_module, "import_module", missing_import)

    with pytest.raises(RagIndexConfigurationError, match="psycopg package"):
        create_rag_index_backend(
            _settings(
                rag_index_backend="pgvector",
                postgres_dsn="postgresql://postgres@localhost/hallu_defense",
            )
        )


def test_create_pgvector_backend_rejects_unsafe_runtime_table_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rag_index_module,
        "_load_psycopg_connect",
        lambda: pytest.fail("psycopg should not load before table validation"),
    )

    with pytest.raises(RagIndexConfigurationError, match="identifier"):
        create_rag_index_backend(
            _settings(
                rag_index_backend="pgvector",
                postgres_dsn="postgresql://postgres@localhost/hallu_defense",
                pgvector_table_name="rag_chunks;drop",
            )
        )


def test_create_pgvector_backend_rejects_dimension_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rag_index_module,
        "_load_psycopg_connect",
        lambda: pytest.fail("psycopg should not load before dimension validation"),
    )

    with pytest.raises(RagIndexConfigurationError, match="EMBEDDING_DIMENSION=16"):
        create_rag_index_backend(
            _settings(
                rag_index_backend="pgvector",
                postgres_dsn="postgresql://postgres@localhost/hallu_defense",
                rag_embedding_dimension=4,
            )
        )


def test_psycopg_pgvector_connection_wraps_connection_errors() -> None:
    connection = PsycopgPgVectorConnection(
        dsn="postgresql://postgres@localhost/hallu_defense",
        connect=RecordingPgVectorPsycopgConnect(connect_error=RuntimeError("database down")),
    )

    with pytest.raises(RagIndexTransportError, match="pgvector execute_many failed"):
        connection.execute_many("INSERT INTO rag_evidence_chunks VALUES (%s)", [[1]])


def test_psycopg_pgvector_connection_wraps_query_errors() -> None:
    connection = PsycopgPgVectorConnection(
        dsn="postgresql://postgres@localhost/hallu_defense",
        connect=RecordingPgVectorPsycopgConnect(execute_error=RuntimeError("bad query")),
    )

    with pytest.raises(RagIndexTransportError, match="pgvector fetch_all failed"):
        connection.fetch_all("SELECT * FROM rag_evidence_chunks WHERE tenant_id = %s", ["tenant-a"])


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


class FailingRagIndexBackend:
    backend_name = "failing"

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        raise RagIndexTransportError("persistent backend unavailable")

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        raise RagIndexTransportError("persistent backend unavailable")


class RecordingOpenSearchTransport:
    def __init__(
        self,
        search_response: Mapping[str, object] | None = None,
        bulk_response: Mapping[str, object] | None = None,
    ) -> None:
        self.calls: list[
            tuple[
                str,
                str,
                Mapping[str, object] | Sequence[object] | str,
                Mapping[str, str] | None,
                float,
            ]
        ] = []
        self._search_response = search_response or {"hits": {"hits": []}}
        self._bulk_response = bulk_response or {"errors": False}

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append((method, path, body, headers, timeout_seconds))
        if path.endswith("_search"):
            return self._search_response
        if path.startswith("/_index_template/"):
            return {"acknowledged": True}
        return self._bulk_response


class RecordingPgVectorConnection:
    def __init__(self, rows: Sequence[Mapping[str, object]] = ()) -> None:
        self.execute_many_calls: list[tuple[str, Sequence[Sequence[object]]]] = []
        self.fetch_all_calls: list[tuple[str, Sequence[object]]] = []
        self._rows = list(rows)

    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        self.execute_many_calls.append((statement, parameters))

    def fetch_all(self, statement: str, parameters: Sequence[object]) -> Sequence[Mapping[str, object]]:
        self.fetch_all_calls.append((statement, parameters))
        return self._rows


class RecordingPgVectorPsycopgCursor:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]] = (),
        execute_error: Exception | None = None,
    ) -> None:
        self.execute_calls: list[tuple[str, Sequence[object]]] = []
        self.executemany_calls: list[tuple[str, Sequence[Sequence[object]]]] = []
        self._rows = list(rows)
        self._execute_error = execute_error

    def __enter__(self) -> "RecordingPgVectorPsycopgCursor":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        return None

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        if self._execute_error is not None:
            raise self._execute_error
        self.execute_calls.append((statement, parameters))

    def executemany(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        if self._execute_error is not None:
            raise self._execute_error
        self.executemany_calls.append((statement, parameters))

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        return self._rows


class RecordingPgVectorPsycopgConnection:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]] = (),
        execute_error: Exception | None = None,
    ) -> None:
        self.cursor_instance = RecordingPgVectorPsycopgCursor(rows, execute_error)

    def __enter__(self) -> "RecordingPgVectorPsycopgConnection":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        return None

    def cursor(self) -> RecordingPgVectorPsycopgCursor:
        return self.cursor_instance


class RecordingPgVectorPsycopgConnect:
    def __init__(
        self,
        rows: Sequence[Mapping[str, object]] = (),
        execute_error: Exception | None = None,
        connect_error: Exception | None = None,
    ) -> None:
        self.calls: list[tuple[str, object | None]] = []
        self.connections: list[RecordingPgVectorPsycopgConnection] = []
        self._rows = list(rows)
        self._execute_error = execute_error
        self._connect_error = connect_error

    def __call__(
        self,
        conninfo: str,
        *,
        row_factory: object | None = None,
    ) -> RecordingPgVectorPsycopgConnection:
        self.calls.append((conninfo, row_factory))
        if self._connect_error is not None:
            raise self._connect_error
        connection = RecordingPgVectorPsycopgConnection(self._rows, self._execute_error)
        self.connections.append(connection)
        return connection


def _chunk(tenant_id: str = "tenant-a", evidence_id: str = "ev_001_001") -> RagChunk:
    return RagChunk(
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        source_ref="policy-a",
        content="Remote work needs manager approval.",
        authority=Authority.INTERNAL,
        freshness=Freshness(staleness_class=StalenessClass.FRESH),
        metadata={"department": "hr"},
        document_index=1,
        chunk_index=1,
    )


def _opensearch_template() -> dict[str, object]:
    return {
        "index_patterns": ["hallu_evidence*"],
        "template": {
            "mappings": {
                "dynamic": False,
                "properties": {
                    "tenant_id": {"type": "keyword"},
                    "content": {"type": "text"},
                },
            },
        },
        "_meta": {
            "schema_version": "rag-opensearch-template.v1",
            "required_query_filter": "tenant_id",
        },
    }


def _settings(**overrides: object) -> Settings:
    values = {
        "environment": "local",
        "policy_version": "test",
        "auth_required": False,
        "allowed_workspace": Path(".").resolve(),
        "max_command_seconds": 30,
        "max_output_chars": 12000,
    }
    values.update(overrides)
    return Settings(**values)
