from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, cast

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
from hallu_defense.domain.rag_metadata import metadata_filter_token
from hallu_defense.main import app
from hallu_defense.services.ingestion import DocumentIngestionService
from hallu_defense.services.rag_access import RagAccessDeniedError
from hallu_defense.services.rag_index import (
    DeterministicHashEmbedder,
    HybridRagIndexBackend,
    OpenSearchRagIndexBackend,
    PgVectorRagIndexBackend,
    PostgresHybridRevisionLockCoordinator,
    PostgresTenantDeletionFence,
    PsycopgPgVectorConnection,
    RagChunk,
    RagIndexConfigurationError,
    RagIndexTenantDeletedError,
    RagIndexTransportError,
    RagIndexWriteResult,
    RagSearchRequest,
    UrlLibOpenSearchTransport,
    create_rag_index_backend,
)
from hallu_defense.services.secrets import SecretValue
import hallu_defense.services.rag_index as rag_index_module
from hallu_defense.services.retrieval import HybridRetriever

TEST_RETRIEVED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


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
                authority=Authority.INTERNAL,
                metadata={"corpus_id": "hr"},
            ),
            DocumentInput(
                source_ref="policy-b",
                content="First paragraph.",
                authority=Authority.INTERNAL,
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
                authority=Authority.INTERNAL,
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
                freshness=Freshness(
                    retrieved_at=TEST_RETRIEVED_AT,
                    staleness_class=StalenessClass.FRESH,
                ),
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
    indexed_metadata = dict(backend.indexed_chunks[0].metadata)
    document_revision = indexed_metadata.pop("document_revision")
    assert isinstance(document_revision, str)
    assert document_revision.startswith("sha256:")
    assert indexed_metadata == {
        "department": "hr",
        "corpus_id": "hr",
        "owner_tenant_id": "tenant-a",
    }


def test_document_revision_is_stable_on_rerun_and_changes_with_content() -> None:
    backend = RecordingRagIndexBackend()
    ingestor = DocumentIngestionService(HybridRetriever(index_backend=backend))

    def ingest(content: str) -> None:
        ingestor.ingest(
            DocumentIngestionRequest(
                corpus_id="hr",
                documents=[
                    DocumentInput(
                        source_ref="policy-a",
                        content=content,
                        authority=Authority.INTERNAL,
                    )
                ],
            ),
            tenant_id="tenant-a",
            trace_id="tr_revision",
        )

    ingest("Revision one.")
    ingest("Revision one.")
    ingest("Revision two.")

    revisions = [chunk.metadata["document_revision"] for chunk in backend.indexed_chunks]
    assert revisions[0] == revisions[1]
    assert revisions[2] != revisions[1]
    assert len({chunk.evidence_id for chunk in backend.indexed_chunks}) == 1


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
                    freshness=Freshness(
                        retrieved_at=TEST_RETRIEVED_AT,
                        staleness_class=StalenessClass.FRESH,
                    ),
                    structured_content={},
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
                freshness=Freshness(
                    retrieved_at=TEST_RETRIEVED_AT,
                    staleness_class=StalenessClass.FRESH,
                ),
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
                freshness=Freshness(
                    retrieved_at=TEST_RETRIEVED_AT,
                    staleness_class=StalenessClass.FRESH,
                ),
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
    assert path == "/_bulk?refresh=wait_for"
    assert headers == {"content-type": "application/x-ndjson"}
    assert timeout == 3
    assert isinstance(body, list)
    assert body[0]["index"]["_index"] == "hallu_evidence"
    assert body[0]["index"]["_id"] != "ev_001_001"
    assert body[1]["tenant_id"] == "tenant-a"
    assert body[1]["evidence_id"] == "ev_001_001"
    assert body[1]["metadata"] == {"department": "hr"}
    assert body[1]["metadata_filter_tokens"] == [
        metadata_filter_token("department", "hr")
    ]


def test_opensearch_bulk_errors_fail_closed_without_echoing_backend_reason() -> None:
    sensitive_reason = "credential-value\r\nforged-header"
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
                            "reason": sensitive_reason,
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

    with pytest.raises(RagIndexTransportError, match="HTTP status 400") as exc_info:
        backend.index_chunks([_chunk()])
    assert sensitive_reason not in str(exc_info.value)
    assert "forged-header" not in str(exc_info.value)


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


def test_opensearch_health_check_accepts_green_or_yellow_and_is_bounded() -> None:
    for status in ("green", "yellow"):
        transport = RecordingOpenSearchTransport(
            health_response={
                "status": status,
                "timed_out": False,
                "number_of_data_nodes": 1,
            }
        )
        backend = OpenSearchRagIndexBackend(
            endpoint="http://opensearch:9200",
            index_name="hallu_evidence",
            timeout_seconds=1.5,
            transport=transport,
        )

        backend.health_check()

        assert transport.calls == [("GET", "/_cluster/health", {}, None, 1.5)]


@pytest.mark.parametrize(
    "response",
    [
        {"status": "red", "timed_out": False},
        {"status": "yellow", "timed_out": True},
        {"status": "yellow"},
        {"timed_out": False},
        {
            "status": "green",
            "timed_out": False,
            "number_of_data_nodes": 1,
            "error": {},
        },
        {"status": "green", "timed_out": False, "number_of_data_nodes": 0},
    ],
)
def test_opensearch_health_check_rejects_red_timed_out_or_malformed(
    response: Mapping[str, object],
) -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=1,
        transport=RecordingOpenSearchTransport(health_response=response),
    )

    with pytest.raises(RagIndexTransportError, match="not ready"):
        backend.health_check()


@pytest.mark.parametrize(
    "response",
    [
        {"status": "yellow", "timed_out": False, "number_of_data_nodes": 2},
        {"status": "green", "timed_out": False, "number_of_data_nodes": 1},
    ],
)
def test_opensearch_production_health_requires_green_and_two_data_nodes(
    response: Mapping[str, object],
) -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="https://search.example.test",
        index_name="hallu_evidence",
        timeout_seconds=1,
        transport=RecordingOpenSearchTransport(health_response=response),
        require_green_health=True,
        minimum_data_nodes=2,
    )

    with pytest.raises(RagIndexTransportError, match="not ready"):
        backend.health_check()


def test_opensearch_production_health_accepts_redundant_green_cluster() -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="https://search.example.test",
        index_name="hallu_evidence",
        timeout_seconds=1,
        transport=RecordingOpenSearchTransport(
            health_response={
                "status": "green",
                "timed_out": False,
                "number_of_data_nodes": 2,
            }
        ),
        require_green_health=True,
        minimum_data_nodes=2,
    )

    backend.health_check()


@pytest.mark.parametrize(
    ("overrides", "expected_green", "expected_nodes"),
    [
        (
            {
                "environment": "production",
                "opensearch_endpoint": "https://search.example.test",
                "outbound_https_allowed_origins": ("https://search.example.test",),
            },
            True,
            2,
        ),
        (
            {
                "environment": "production",
                "opensearch_endpoint": "http://hallu-defense-opensearch:9200",
                "opensearch_kind_insecure_http_enabled": True,
            },
            False,
            1,
        ),
        ({"environment": "local"}, False, 1),
    ],
)
def test_opensearch_factory_selects_environment_health_policy(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    expected_green: bool,
    expected_nodes: int,
) -> None:
    captured: dict[str, object] = {}

    def capture_backend(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(rag_index_module, "OpenSearchRagIndexBackend", capture_backend)

    rag_index_module.create_opensearch_rag_backend(
        _settings(**overrides),
        secret_manager=None,
    )

    assert captured["require_green_health"] is expected_green
    assert captured["minimum_data_nodes"] == expected_nodes


def test_opensearch_transport_adds_secret_authorization_to_bulk_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_open(req: object, **kwargs: object) -> StaticJsonHttpResponse:
        captured["request"] = req
        captured.update(kwargs)
        return StaticJsonHttpResponse(b'{"errors":false}')

    monkeypatch.setattr(rag_index_module, "open_url_no_redirect", fake_open)
    transport = UrlLibOpenSearchTransport(
        "https://search.example.test",
        authorization=SecretValue(
            name="rag/opensearch/authorization",
            _value="Bearer fixture-token",
        ),
    )

    transport.request_json(
        "POST",
        "/_bulk?refresh=wait_for",
        [{"index": {}}],
        headers={"content-type": "application/x-ndjson"},
        timeout_seconds=2,
    )

    req = captured["request"]
    headers = {name.lower(): value for name, value in req.header_items()}  # type: ignore[union-attr]
    assert headers["authorization"] == "Bearer fixture-token"
    assert headers["content-type"] == "application/x-ndjson"


def test_opensearch_transport_rejects_authorization_override_without_secret_leak() -> None:
    secret = "Bearer configured-secret"
    transport = UrlLibOpenSearchTransport(
        "https://search.example.test",
        authorization=SecretValue(name="rag/opensearch/authorization", _value=secret),
    )

    with pytest.raises(RagIndexTransportError, match="cannot override") as exc_info:
        transport.request_json(
            "GET",
            "/_cluster/health",
            {},
            headers={"Authorization": "Bearer caller-value"},
            timeout_seconds=1,
        )

    assert secret not in str(exc_info.value)
    assert "caller-value" not in str(exc_info.value)


@pytest.mark.parametrize(
    "value",
    [
        "Bearer fixture-token\r\nX-Injected: value",
        "Bearer fixture-token\x7f",
        "Digest fixture-token",
        "Bearer " + ("a" * 8192),
    ],
)
def test_opensearch_transport_rejects_invalid_authorization_secret_safely(
    value: str,
) -> None:
    with pytest.raises(RagIndexConfigurationError, match="secret is invalid") as exc_info:
        UrlLibOpenSearchTransport(
            "https://search.example.test",
            authorization=SecretValue(name="rag/opensearch/authorization", _value=value),
        )

    assert value not in str(exc_info.value)


def test_opensearch_factory_loads_authorization_and_optional_ca_from_secret_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca_path = tmp_path / "opensearch-ca.pem"
    ca_path.write_text("fixture CA", encoding="utf-8")
    ssl_context = object()
    captured: dict[str, object] = {}
    manager = StaticRagSecretManager(
        {"rag/opensearch/authorization": "ApiKey fixture-token"}
    )

    def fake_context(*, cafile: str) -> object:
        captured["cafile"] = cafile
        return ssl_context

    def fake_transport(endpoint: str, **kwargs: object) -> RecordingOpenSearchTransport:
        captured["endpoint"] = endpoint
        captured.update(kwargs)
        return RecordingOpenSearchTransport()

    monkeypatch.setattr(rag_index_module.ssl, "create_default_context", fake_context)
    monkeypatch.setattr(rag_index_module, "UrlLibOpenSearchTransport", fake_transport)

    backend = create_rag_index_backend(
        _settings(
            rag_index_backend="opensearch",
            opensearch_endpoint="https://search.example.test",
            opensearch_authorization_secret_name="rag/opensearch/authorization",
            opensearch_ca_cert_path=ca_path,
        ),
        manager,
    )

    assert isinstance(backend, OpenSearchRagIndexBackend)
    assert manager.requested == ["rag/opensearch/authorization"]
    assert captured["cafile"] == str(ca_path)
    assert captured["ssl_context"] is ssl_context
    authorization = captured["authorization"]
    assert isinstance(authorization, SecretValue)
    assert repr(authorization) == (
        "SecretValue(name='rag/opensearch/authorization', value='[redacted]')"
    )


def test_opensearch_transport_enforces_request_size_boundary_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    def fake_open(req: object, **_kwargs: object) -> StaticJsonHttpResponse:
        calls.append(req)
        return StaticJsonHttpResponse(b"{}")

    monkeypatch.setattr(rag_index_module, "open_url_no_redirect", fake_open)
    transport = UrlLibOpenSearchTransport("https://search.example.test")
    boundary = "a" * rag_index_module.MAX_OPENSEARCH_HTTP_REQUEST_BYTES

    transport.request_json("POST", "/_bulk", boundary, timeout_seconds=1)
    with pytest.raises(RagIndexTransportError, match="safety limit") as exc_info:
        transport.request_json("POST", "/_bulk", boundary + "a", timeout_seconds=1)

    assert len(calls) == 1
    assert str(len(boundary)) not in str(exc_info.value)


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
                            "freshness": {
                                "retrieved_at": "2026-01-01T00:00:00+00:00",
                                "staleness_class": "fresh",
                            },
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
    assert {
        "term": {
            "metadata_filter_tokens": metadata_filter_token("department", "hr")
        }
    } in filters
    assert {"terms": {"source_ref": ["policy-a"]}} in filters
    assert [item.evidence_id for item in evidence] == ["ev_a"]
    assert evidence[0].structured_content["retrieval"]["tenant_scoped"] is True
    assert evidence[0].structured_content["structure"] == {
        "section_heading": "Remote policy",
        "section_path": ["Handbook", "Remote policy"],
        "section_level": 2,
        "chunk_kind": "section",
    }


def test_opensearch_search_fails_closed_on_cross_tenant_hit() -> None:
    transport = RecordingOpenSearchTransport(
        search_response={
            "hits": {
                "hits": [
                    {
                        "_score": 99,
                        "_source": {
                            "tenant_id": "tenant-b",
                            "evidence_id": "ev_b",
                            "source_ref": "policy-b",
                            "content": "Cross-tenant evidence must fail closed.",
                            "authority": "internal",
                            "metadata": {"department": "hr"},
                            "freshness": {
                                "retrieved_at": "2026-01-01T00:00:00+00:00",
                                "staleness_class": "fresh",
                            },
                        },
                    }
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

    with pytest.raises(RagIndexTransportError, match="tenant_id"):
        backend.search(
            RagSearchRequest(
                tenant_id="tenant-a",
                claim_id="clm_remote",
                query_text="remote policy",
            )
        )


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"error": {"reason": "sensitive backend detail"}},
        {"hits": {}},
        {"hits": {"hits": "invalid"}},
        {"hits": {"hits": [None]}},
        {"hits": {"hits": [{}]}},
    ],
)
def test_opensearch_search_rejects_malformed_success_payloads(
    response: dict[str, object],
) -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=RecordingOpenSearchTransport(search_response=response),
    )

    with pytest.raises(RagIndexTransportError) as exc_info:
        backend.search(_search_request())

    assert "sensitive backend detail" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("metadata", []),
        ("authority", "administrator"),
        ("freshness", None),
        (
            "freshness",
            {"retrieved_at": "2026-01-01T00:00:00", "staleness_class": "fresh"},
        ),
        (
            "freshness",
            {
                "retrieved_at": "2026-01-01T00:00:00+00:00",
                "staleness_class": "recent",
            },
        ),
        ("source_ref", "policy\x00forged"),
        ("content", "policy\ud800forged"),
    ],
)
def test_opensearch_search_rejects_corrupt_persistent_fields(
    field_name: str,
    invalid_value: object,
) -> None:
    source = _valid_opensearch_source()
    source[field_name] = invalid_value
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=RecordingOpenSearchTransport(
            search_response={"hits": {"hits": [{"_score": 1.0, "_source": source}]}},
        ),
    )

    with pytest.raises(RagIndexTransportError):
        backend.search(_search_request())


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


def test_lexical_feature_hash_embedder_is_deterministic_and_normalized() -> None:
    embedder = DeterministicHashEmbedder(dimension=16)
    text = "Remote WORK requires manager approval."

    first = embedder.embed(text)
    second = embedder.embed(text)

    assert first == second
    assert len(first) == 16
    assert math.sqrt(sum(value * value for value in first)) == pytest.approx(1.0)


def test_lexical_feature_hash_ranks_overlapping_paraphrase_above_irrelevant_text() -> None:
    embedder = DeterministicHashEmbedder(dimension=16)
    query = embedder.embed("Remote work requires manager approval")
    overlapping = embedder.embed(
        "Manager approval is required for remote work requests"
    )
    irrelevant = embedder.embed(
        "Quarterly database backups use encrypted storage retention"
    )

    overlapping_similarity = sum(
        left * right for left, right in zip(query, overlapping, strict=True)
    )
    irrelevant_similarity = sum(
        left * right for left, right in zip(query, irrelevant, strict=True)
    )

    assert overlapping_similarity > irrelevant_similarity


@pytest.mark.parametrize("text", ["", "   \n\t"])
def test_lexical_feature_hash_empty_input_is_stable_zero_vector(text: str) -> None:
    embedding = DeterministicHashEmbedder(dimension=16).embed(text)

    assert embedding == [0.0] * 16


@pytest.mark.parametrize("text", ["___", "!!!", "🛡️"])
def test_lexical_feature_hash_nonblank_fallback_is_deterministic_nonzero(
    text: str,
) -> None:
    embedder = DeterministicHashEmbedder(dimension=16)

    first = embedder.embed(text)
    second = embedder.embed(text)

    assert first == second
    assert any(value != 0 for value in first)
    assert math.sqrt(sum(value * value for value in first)) == pytest.approx(1.0)


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
                "retrieved_at": TEST_RETRIEVED_AT,
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
    assert (
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::vector)"
        in insert_statement
    )
    assert insert_parameters[0][0] == "tenant-a"
    assert insert_parameters[0][1] == "ev_001_001"

    search_statement, search_parameters = connection.fetch_all_calls[0]
    assert "tenant_id = %s" in search_statement
    assert "source_ref = ANY(%s)" in search_statement
    assert "metadata @> %s::jsonb AND metadata -> %s = %s::jsonb" in search_statement
    assert "1 - (embedding <=> %s::vector) AS vector_score" in search_statement
    assert "ORDER BY vector_score DESC, evidence_id ASC" in search_statement
    assert isinstance(search_parameters[0], str) and search_parameters[0].startswith("[")
    assert search_parameters[1] == "tenant-a"
    assert search_parameters[2] == ["policy-a"]
    assert search_parameters[3:6] == [
        '{"department":"hr"}',
        "department",
        '"hr"',
    ]
    assert search_parameters[-1] == 3
    assert [item.evidence_id for item in evidence] == ["ev_pg"]


@pytest.mark.parametrize(
    ("metadata_filter", "context_refs", "expected_tail"),
    [
        ({}, [], ["tenant-a", 2]),
        (
            {"z_filter": ["a", "b"], "a_filter": {"enabled": True}},
            ["policy-a"],
            [
                "tenant-a",
                ["policy-a"],
                '{"a_filter":{"enabled":true}}',
                "a_filter",
                '{"enabled":true}',
                '{"z_filter":["a","b"]}',
                "z_filter",
                '["a","b"]',
                2,
            ],
        ),
    ],
)
def test_pgvector_search_parameters_follow_sql_placeholder_order(
    metadata_filter: dict[str, object],
    context_refs: list[str],
    expected_tail: list[object],
) -> None:
    connection = RecordingPgVectorConnection()
    backend = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks",
        connection=connection,
    )

    backend.search(
        RagSearchRequest(
            tenant_id="tenant-a",
            claim_id="clm_order",
            query_text="exact placeholder order",
            metadata_filter=metadata_filter,
            context_refs=context_refs,
            max_results=2,
        )
    )

    statement, parameters = connection.fetch_all_calls[0]
    assert isinstance(parameters[0], str) and parameters[0].startswith("[")
    assert list(parameters[1:]) == expected_tail
    assert statement.count("metadata -> %s = %s::jsonb") == len(metadata_filter)
    assert statement.count("metadata @> %s::jsonb") == len(metadata_filter)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("metadata", "not-json"),
        ("authority", "administrator"),
        ("retrieved_at", None),
        ("retrieved_at", datetime(2026, 1, 1)),
        ("published_at", datetime(2026, 1, 1)),
        ("staleness_class", "recent"),
        ("content", "policy\x00forged"),
    ],
)
def test_pgvector_search_rejects_corrupt_persistent_rows(
    field_name: str,
    invalid_value: object,
) -> None:
    row = _valid_pgvector_row()
    row[field_name] = invalid_value
    backend = PgVectorRagIndexBackend(
        table_name="rag_evidence_chunks",
        connection=RecordingPgVectorConnection(rows=[row]),
    )

    with pytest.raises(RagIndexTransportError):
        backend.search(_search_request())


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
                "retrieved_at": TEST_RETRIEVED_AT,
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
    sentinel = "postgresql://postgres:secret@localhost/hallu private insert"
    connection = PsycopgPgVectorConnection(
        dsn="postgresql://postgres:secret@localhost/hallu_defense",
        connect=RecordingPgVectorPsycopgConnect(connect_error=RuntimeError(sentinel)),
    )

    with pytest.raises(RagIndexTransportError, match="pgvector execute_many failed") as exc_info:
        connection.execute_many("INSERT INTO rag_evidence_chunks VALUES (%s)", [[1]])
    assert sentinel not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_psycopg_pgvector_connection_wraps_query_errors() -> None:
    sentinel = "bad query with tenant-secret and private parameters"
    connection = PsycopgPgVectorConnection(
        dsn="postgresql://postgres@localhost/hallu_defense",
        connect=RecordingPgVectorPsycopgConnect(execute_error=RuntimeError(sentinel)),
    )

    with pytest.raises(RagIndexTransportError, match="pgvector fetch_all failed") as exc_info:
        connection.fetch_all("SELECT * FROM rag_evidence_chunks WHERE tenant_id = %s", ["tenant-a"])
    assert sentinel not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_psycopg_pgvector_connection_sanitizes_transactional_write_errors() -> None:
    sentinel = "postgresql://writer:dsn-secret@postgres/db private metadata"
    connection = PsycopgPgVectorConnection(
        dsn="postgresql://writer:dsn-secret@postgres/db",
        connect=RecordingPgVectorPsycopgConnect(execute_error=RuntimeError(sentinel)),
    )

    with pytest.raises(RagIndexTransportError, match="transactional write failed") as exc_info:
        connection.execute_many_transactionally((("INSERT private", [["secret"]]),))

    assert sentinel not in str(exc_info.value)
    assert "dsn-secret" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_psycopg_pgvector_connection_executes_reconciliation_in_one_transaction() -> None:
    connect = RecordingPgVectorPsycopgConnect()
    connection = PsycopgPgVectorConnection(
        dsn="postgresql://postgres@localhost/hallu_defense",
        connect=connect,
    )

    connection.execute_many_transactionally(
        (
            ("INSERT INTO rag_evidence_chunks VALUES (%s)", [["insert"]]),
            ("DELETE FROM rag_evidence_chunks WHERE tenant_id = %s", [["tenant-a"]]),
        )
    )

    assert len(connect.connections) == 1
    assert connect.connections[0].cursor_instance.executemany_calls == [
        ("INSERT INTO rag_evidence_chunks VALUES (%s)", [["insert"]]),
        ("DELETE FROM rag_evidence_chunks WHERE tenant_id = %s", [["tenant-a"]]),
    ]


def test_opensearch_revision_reconciliation_is_scoped_and_waits_for_refresh() -> None:
    transport = RecordingOpenSearchTransport()
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )
    chunk = _chunk()
    chunk = replace(
        chunk,
        metadata={
            "corpus_id": "corpus-a",
            "document_revision": "sha256:new",
        },
    )

    backend.index_chunks([chunk])

    assert transport.calls[0][1] == "/_bulk?refresh=wait_for"
    method, path, body, _headers, _timeout = transport.calls[1]
    assert method == "POST"
    assert path == (
        "/hallu_evidence/_delete_by_query?conflicts=proceed&refresh=true"
    )
    assert isinstance(body, Mapping)
    bool_query = body["query"]["bool"]
    assert {"term": {"tenant_id": "tenant-a"}} in bool_query["filter"]
    assert {"term": {"source_ref": "policy-a"}} in bool_query["filter"]
    assert {"term": {"corpus_id": "corpus-a"}} in bool_query["filter"]
    keep_filter = bool_query["must_not"][0]["bool"]["filter"]
    assert {"term": {"document_revision": "sha256:new"}} in keep_filter
    assert {"terms": {"evidence_id": ["ev_001_001"]}} in keep_filter


def test_opensearch_lifecycle_deletion_is_tenant_scoped_and_verified() -> None:
    transport = RecordingOpenSearchTransport(
        deletion_response={
            "timed_out": False,
            "version_conflicts": 0,
            "failures": [],
            "deleted": 2,
        },
        count_response={"count": 0},
    )
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    deleted = backend.delete_evidence_ids(
        tenant_id="tenant-a",
        evidence_ids=["ev_b", "ev_a"],
    )

    assert deleted == 2
    assert [call[1] for call in transport.calls] == [
        "/hallu_evidence/_delete_by_query?conflicts=proceed&refresh=true",
        "/hallu_evidence/_count",
    ]
    query = transport.calls[0][2]
    assert isinstance(query, Mapping)
    assert query["query"]["bool"]["filter"] == [
        {"term": {"tenant_id": "tenant-a"}},
        {"terms": {"evidence_id": ["ev_a", "ev_b"]}},
    ]
    assert transport.calls[1][2] == query


def test_opensearch_tenant_deletion_removes_all_documents_and_verifies_zero() -> None:
    transport = RecordingOpenSearchTransport(
        deletion_response={
            "timed_out": False,
            "version_conflicts": 0,
            "failures": [],
            "deleted": 3,
        },
        count_response={"count": 0},
    )
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )

    assert backend.delete_tenant(tenant_id="tenant-a") == 3

    query = {"query": {"term": {"tenant_id": "tenant-a"}}}
    assert [call[1] for call in transport.calls] == [
        "/hallu_evidence/_delete_by_query?conflicts=proceed&refresh=true",
        "/hallu_evidence/_count",
    ]
    assert transport.calls[0][2] == query
    assert transport.calls[1][2] == query


@pytest.mark.parametrize(
    "deletion_response",
    [
        {"timed_out": True, "version_conflicts": 0, "failures": [], "deleted": 0},
        {"timed_out": False, "version_conflicts": 1, "failures": [], "deleted": 0},
        {
            "timed_out": False,
            "version_conflicts": 0,
            "failures": [{"reason": "blocked"}],
            "deleted": 0,
        },
    ],
)
def test_opensearch_lifecycle_deletion_fails_closed(
    deletion_response: Mapping[str, object],
) -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=RecordingOpenSearchTransport(deletion_response=deletion_response),
    )

    with pytest.raises(RagIndexTransportError, match="lifecycle deletion failed"):
        backend.delete_evidence_ids(tenant_id="tenant-a", evidence_ids=["ev_a"])


def test_opensearch_lifecycle_deletion_rejects_remaining_documents() -> None:
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=RecordingOpenSearchTransport(
            deletion_response={
                "timed_out": False,
                "version_conflicts": 0,
                "failures": [],
                "deleted": 1,
            },
            count_response={"count": 1},
        ),
    )

    with pytest.raises(RagIndexTransportError, match="parity verification"):
        backend.delete_evidence_ids(tenant_id="tenant-a", evidence_ids=["ev_a"])


@pytest.mark.parametrize(
    "response",
    [
        {"timed_out": True, "version_conflicts": 0, "failures": []},
        {"timed_out": False, "version_conflicts": 1, "failures": []},
        {"timed_out": False, "version_conflicts": 0, "failures": [{"reason": "x"}]},
    ],
)
def test_opensearch_revision_reconciliation_fails_closed(
    response: Mapping[str, object],
) -> None:
    transport = RecordingOpenSearchTransport(reconciliation_response=response)
    backend = OpenSearchRagIndexBackend(
        endpoint="http://opensearch:9200",
        index_name="hallu_evidence",
        timeout_seconds=3,
        transport=transport,
    )
    base = _chunk()
    chunk = replace(
        base,
        metadata={
            "corpus_id": "corpus-a",
            "document_revision": "sha256:new",
        },
    )

    with pytest.raises(RagIndexTransportError, match="reconciliation"):
        backend.index_chunks([chunk])


def test_hybrid_revision_locks_are_sorted_bounded_and_released_in_reverse() -> None:
    connect = RecordingHybridLockConnect()
    row_factory = object()
    coordinator = PostgresHybridRevisionLockCoordinator(
        dsn="postgresql://lock-user:credential@postgres/hallu",
        connect=connect,
        timeout_seconds=1.25,
        row_factory=row_factory,
    )

    with coordinator.hold(["source-b", "source-a", "source-a"]):
        connect.events.append("body")

    assert connect.calls == [
        {
            "conninfo": "postgresql://lock-user:credential@postgres/hallu",
            "autocommit": True,
            "connect_timeout": 2,
            "options": "-c lock_timeout=1250 -c statement_timeout=1250",
            "row_factory": row_factory,
        }
    ]
    lock_parameters = [
        parameters[0]
        for statement, parameters in connect.cursor.execute_calls
        if "pg_advisory_lock" in statement
    ]
    unlock_parameters = [
        parameters[0]
        for statement, parameters in connect.cursor.execute_calls
        if "pg_advisory_unlock" in statement
    ]
    assert lock_parameters == [
        "hybrid_revision_v1:source-a",
        "hybrid_revision_v1:source-b",
    ]
    assert unlock_parameters == [
        "hybrid_revision_v1:source-b",
        "hybrid_revision_v1:source-a",
    ]
    assert connect.events == ["connect", "body", "close"]


def test_hybrid_revision_lock_timeout_fails_closed_without_dsn_leak() -> None:
    dsn = "postgresql://lock-user:dsn-secret@postgres/hallu"
    connect = RecordingHybridLockConnect(
        execute_error=TimeoutError(f"statement cancelled for {dsn}")
    )
    coordinator = PostgresHybridRevisionLockCoordinator(
        dsn=dsn,
        connect=connect,
        timeout_seconds=0.1,
    )

    with pytest.raises(RagIndexTransportError, match="acquisition failed") as exc_info:
        with coordinator.hold(["source-a"]):
            pytest.fail("timed out lock must never enter the protected body")

    assert dsn not in str(exc_info.value)
    assert "dsn-secret" not in str(exc_info.value)
    assert connect.closed is True


def test_hybrid_factory_propagates_rag_timeout_to_revision_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opensearch = RecordingExactRagBackend("opensearch")
    pgvector = RecordingExactRagBackend("pgvector")
    lock_capture: dict[str, object] = {}
    lock_coordinator = RecordingRevisionLocks([])

    monkeypatch.setattr(
        rag_index_module,
        "create_opensearch_rag_backend",
        lambda settings, secret_manager: opensearch,
    )
    monkeypatch.setattr(
        rag_index_module,
        "_load_psycopg_connect",
        lambda: (object(), "dict-row"),
    )
    monkeypatch.setattr(
        rag_index_module,
        "_create_pgvector_backend",
        lambda settings, connect, row_factory: pgvector,
    )

    def build_lock(**kwargs: object) -> RecordingRevisionLocks:
        lock_capture.update(kwargs)
        return lock_coordinator

    monkeypatch.setattr(
        rag_index_module,
        "PostgresHybridRevisionLockCoordinator",
        build_lock,
    )

    backend = create_rag_index_backend(
        _settings(
            rag_index_backend="hybrid",
            postgres_dsn="postgresql://postgres/hallu",
            opensearch_endpoint="http://opensearch:9200",
            rag_index_timeout_seconds=2.75,
        )
    )

    assert isinstance(backend, HybridRagIndexBackend)
    assert lock_capture["timeout_seconds"] == 2.75


def test_hybrid_write_serializes_every_source_and_writes_opensearch_first() -> None:
    events: list[str] = []
    opensearch = RecordingExactRagBackend("opensearch", events=events)
    pgvector = RecordingExactRagBackend("pgvector", events=events)
    locks = RecordingRevisionLocks(events)
    backend = HybridRagIndexBackend(
        opensearch=opensearch,
        pgvector=pgvector,
        revision_locks=locks,
        tenant_write_fence=RecordingTenantWriteFence(events),
    )

    result = backend.index_chunks([_chunk()])

    assert result.backend == "hybrid"
    assert result.evidence_ids == ["ev_001_001"]
    assert locks.lock_batches == [
        [
            '["tenant-a","__tenant_lifecycle__"]',
            '["tenant-a","policy-a",""]',
        ]
    ]
    assert events == [
        "lock-enter",
        "tenant-fence",
        "index:opensearch",
        "index:pgvector",
        "lock-exit",
    ]


def test_hybrid_write_fails_closed_after_opensearch_partial_success() -> None:
    events: list[str] = []
    opensearch = RecordingExactRagBackend("opensearch", events=events)
    pgvector = RecordingExactRagBackend(
        "pgvector",
        events=events,
        index_error=RagIndexTransportError("pg unavailable"),
    )
    backend = HybridRagIndexBackend(
        opensearch=opensearch,
        pgvector=pgvector,
        revision_locks=RecordingRevisionLocks(events),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="pg unavailable"):
        backend.index_chunks([_chunk()])

    assert events == ["lock-enter", "index:opensearch", "index:pgvector", "lock-exit"]
    assert len(opensearch.indexed_chunks) == 1
    assert pgvector.indexed_chunks == []


def test_hybrid_tenant_deletion_removes_opensearch_orphan_after_partial_write() -> None:
    events: list[str] = []
    opensearch = RecordingExactRagBackend("opensearch", events=events)
    pgvector = RecordingExactRagBackend(
        "pgvector",
        events=events,
        index_error=RagIndexTransportError("pg unavailable"),
    )
    backend = HybridRagIndexBackend(
        opensearch=opensearch,
        pgvector=pgvector,
        revision_locks=RecordingRevisionLocks(events),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="pg unavailable"):
        backend.index_chunks([_chunk()])

    assert len(opensearch.indexed_chunks) == 1
    assert backend.delete_tenant(tenant_id="tenant-a") == 1
    assert opensearch.indexed_chunks == []
    assert pgvector.indexed_chunks == []
    assert opensearch.delete_tenant_calls == ["tenant-a"]


def test_hybrid_write_rejects_tombstoned_tenant_before_opensearch() -> None:
    events: list[str] = []
    opensearch = RecordingExactRagBackend("opensearch", events=events)
    pgvector = RecordingExactRagBackend("pgvector", events=events)
    fence_connection = RecordingPgVectorConnection(
        [{"tenant_id": "tenant-a"}]
    )
    backend = HybridRagIndexBackend(
        opensearch=opensearch,
        pgvector=pgvector,
        revision_locks=RecordingRevisionLocks(events),
        tenant_write_fence=PostgresTenantDeletionFence(fence_connection),
    )

    with pytest.raises(RagIndexTenantDeletedError, match="durably deleted tenant"):
        backend.index_chunks([_chunk()])

    assert events == ["lock-enter", "lock-exit"]
    assert opensearch.indexed_chunks == []
    assert pgvector.indexed_chunks == []
    assert len(fence_connection.fetch_all_calls) == 1
    statement, parameters = fence_connection.fetch_all_calls[0]
    assert "rag_tenant_deletion_tombstones" in statement
    assert parameters == (["tenant-a"],)


def test_hybrid_search_exact_lookup_then_rrf_and_quality_rerank() -> None:
    first = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="opensearch_bm25_v1",
        score=8.0,
    )
    second = _persistent_evidence(
        "ev_b",
        content="Beta policy",
        ranker="opensearch_bm25_v1",
        score=4.0,
    )
    vector_first = _persistent_evidence(
        "ev_b",
        content="Beta policy",
        ranker="pgvector_cosine_v1",
        score=0.95,
    )
    vector_second = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="pgvector_cosine_v1",
        score=0.75,
    )
    exact = {
        "ev_a": _persistent_evidence(
            "ev_a",
            content="Alpha policy",
            ranker="exact",
            score=None,
        ),
        "ev_b": _persistent_evidence(
            "ev_b",
            content="Beta policy",
            ranker="exact",
            score=None,
        ),
    }
    opensearch = RecordingExactRagBackend(
        "opensearch",
        search_results=[first, second],
        exact_results=exact,
    )
    pgvector = RecordingExactRagBackend(
        "pgvector",
        search_results=[vector_first, vector_second],
        exact_results=exact,
    )
    backend = HybridRagIndexBackend(
        opensearch=opensearch,
        pgvector=pgvector,
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    evidence = backend.search(_search_request(max_results=2))

    assert [item.evidence_id for item in evidence] == ["ev_a", "ev_b"]
    assert opensearch.lookup_calls == [("tenant-a", ("ev_a", "ev_b"))]
    assert pgvector.lookup_calls == [("tenant-a", ("ev_a", "ev_b"))]
    retrieval = evidence[0].structured_content["retrieval"]
    assert retrieval["ranker"] == "persistent_hybrid_rrf_v1"
    assert retrieval["fused_rank"] == 1
    assert retrieval["rrf_score"] > 0
    assert retrieval["authority_score"] == 0.85
    assert retrieval["freshness_score"] == 1.0
    assert retrieval["rankers"] == {
        "opensearch_bm25_v1": {"matched": True, "rank": 1, "score": 8.0},
        "pgvector_cosine_v1": {"matched": True, "rank": 2, "score": 0.75},
    }
    assert (
        evidence[0].structured_content["retrieval"]["rrf_score"]
        == evidence[1].structured_content["retrieval"]["rrf_score"]
    )


@pytest.mark.parametrize("failing_backend", ["opensearch", "pgvector"])
def test_hybrid_search_fails_closed_when_either_ranker_transport_fails(
    failing_backend: str,
) -> None:
    error = RagIndexTransportError(f"{failing_backend} unavailable")
    backend = HybridRagIndexBackend(
        opensearch=RecordingExactRagBackend(
            "opensearch",
            search_error=error if failing_backend == "opensearch" else None,
        ),
        pgvector=RecordingExactRagBackend(
            "pgvector",
            search_error=error if failing_backend == "pgvector" else None,
        ),
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="unavailable"):
        backend.search(_search_request())


def test_hybrid_search_rejects_partial_exact_lookup() -> None:
    ranked = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="opensearch_bm25_v1",
        score=2.0,
    )
    exact = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="exact",
        score=None,
    )
    backend = HybridRagIndexBackend(
        opensearch=RecordingExactRagBackend(
            "opensearch",
            search_results=[ranked],
            exact_results={"ev_a": exact},
        ),
        pgvector=RecordingExactRagBackend("pgvector", exact_results={}),
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="partial persistent write"):
        backend.search(_search_request())


def test_hybrid_search_rejects_exact_chunk_count_mismatch() -> None:
    ranked = [
        _persistent_evidence(
            evidence_id,
            content=f"Policy {evidence_id}",
            ranker="opensearch_bm25_v1",
            score=score,
        )
        for evidence_id, score in (("ev_a", 2.0), ("ev_b", 1.0))
    ]
    exact = {
        evidence_id: _persistent_evidence(
            evidence_id,
            content=f"Policy {evidence_id}",
            ranker="exact",
            score=None,
        )
        for evidence_id in ("ev_a", "ev_b")
    }
    backend = HybridRagIndexBackend(
        opensearch=RecordingExactRagBackend(
            "opensearch",
            search_results=ranked,
            exact_results=exact,
        ),
        pgvector=RecordingExactRagBackend(
            "pgvector",
            exact_results={"ev_a": exact["ev_a"]},
        ),
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="partial persistent write"):
        backend.search(_search_request())


def test_hybrid_search_rejects_duplicate_ranker_evidence_id() -> None:
    duplicate = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="opensearch_bm25_v1",
        score=2.0,
    )
    backend = HybridRagIndexBackend(
        opensearch=RecordingExactRagBackend(
            "opensearch",
            search_results=[duplicate, duplicate],
        ),
        pgvector=RecordingExactRagBackend("pgvector"),
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="duplicate evidence_id"):
        backend.search(_search_request())


@pytest.mark.parametrize("field", ["content", "source_ref", "metadata", "tenant_id"])
def test_hybrid_search_rejects_canonical_backend_disagreement(field: str) -> None:
    opensearch_ranked = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="opensearch_bm25_v1",
        score=2.0,
    )
    pgvector_ranked = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="pgvector_cosine_v1",
        score=0.8,
    )
    opensearch_exact = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="exact",
        score=None,
    )
    changes: dict[str, object] = {}
    if field == "content":
        changes["content"] = "Conflicting policy"
    elif field == "source_ref":
        changes["source_ref"] = "other-source"
    elif field == "metadata":
        changes["metadata"] = {"department": "finance"}
    else:
        changes["tenant_id"] = "tenant-b"
    pgvector_exact = _persistent_evidence(
        "ev_a",
        content=cast(str, changes.get("content", "Alpha policy")),
        source_ref=cast(str, changes.get("source_ref", "policy-a")),
        metadata=cast(dict[str, object], changes.get("metadata", {"department": "hr"})),
        tenant_id=cast(str, changes.get("tenant_id", "tenant-a")),
        ranker="exact",
        score=None,
    )
    backend = HybridRagIndexBackend(
        opensearch=RecordingExactRagBackend(
            "opensearch",
            search_results=[opensearch_ranked],
            exact_results={"ev_a": opensearch_exact},
        ),
        pgvector=RecordingExactRagBackend(
            "pgvector",
            search_results=[pgvector_ranked],
            exact_results={"ev_a": pgvector_exact},
        ),
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="tenant trace|disagree"):
        backend.search(_search_request())


def test_hybrid_canonical_comparison_rejects_retrieval_time_disagreement() -> None:
    older_read = datetime(2026, 1, 1, tzinfo=timezone.utc)
    newer_read = datetime(2026, 1, 2, tzinfo=timezone.utc)
    opensearch_exact = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="exact",
        score=None,
        retrieved_at=older_read,
    )
    pgvector_exact = _persistent_evidence(
        "ev_a",
        content="Alpha policy",
        ranker="exact",
        score=None,
        retrieved_at=newer_read,
    )
    backend = HybridRagIndexBackend(
        opensearch=RecordingExactRagBackend(
            "opensearch",
            exact_results={"ev_a": opensearch_exact},
        ),
        pgvector=RecordingExactRagBackend(
            "pgvector",
            exact_results={"ev_a": pgvector_exact},
        ),
        revision_locks=RecordingRevisionLocks([]),
        tenant_write_fence=AllowingTenantWriteFence(),
    )

    with pytest.raises(RagIndexTransportError, match="disagree"):
        backend.fetch_by_ids(tenant_id="tenant-a", evidence_ids=["ev_a"])


class RecordingHybridLockCursor:
    def __init__(self, execute_error: Exception | None = None) -> None:
        self.execute_error = execute_error
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self) -> "RecordingHybridLockCursor":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        return None

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        if self.execute_error is not None:
            raise self.execute_error
        self.execute_calls.append((statement, tuple(parameters)))

    def fetchone(self) -> Mapping[str, object]:
        return {"unlocked": True}


class RecordingHybridLockConnection:
    def __init__(self, owner: "RecordingHybridLockConnect") -> None:
        self._owner = owner

    def cursor(self) -> RecordingHybridLockCursor:
        return self._owner.cursor

    def close(self) -> None:
        self._owner.closed = True
        self._owner.events.append("close")


class RecordingHybridLockConnect:
    def __init__(self, execute_error: Exception | None = None) -> None:
        self.cursor = RecordingHybridLockCursor(execute_error)
        self.calls: list[dict[str, object]] = []
        self.events: list[str] = []
        self.closed = False

    def __call__(
        self,
        conninfo: str,
        *,
        autocommit: bool,
        connect_timeout: int,
        options: str,
        row_factory: object | None = None,
    ) -> RecordingHybridLockConnection:
        self.calls.append(
            {
                "conninfo": conninfo,
                "autocommit": autocommit,
                "connect_timeout": connect_timeout,
                "options": options,
                "row_factory": row_factory,
            }
        )
        self.events.append("connect")
        return RecordingHybridLockConnection(self)


class StaticJsonHttpResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> "StaticJsonHttpResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            return self._payload
        return self._payload[:amount]


class StaticRagSecretManager:
    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)
        self.requested: list[str] = []

    def get_secret(self, name: str, *, field: str = "value") -> SecretValue:
        self.requested.append(name)
        if field != "value" or name not in self._values:
            raise RuntimeError("secret unavailable")
        return SecretValue(name=name, _value=self._values[name])


class RecordingExactRagBackend:
    def __init__(
        self,
        backend_name: str,
        *,
        events: list[str] | None = None,
        search_results: Sequence[Evidence] = (),
        exact_results: Mapping[str, Evidence] | None = None,
        index_error: Exception | None = None,
        search_error: Exception | None = None,
        lookup_error: Exception | None = None,
        deleted_count: int = 0,
    ) -> None:
        self.backend_name = backend_name
        self.events = events if events is not None else []
        self.search_results = list(search_results)
        self.exact_results = dict(exact_results or {})
        self.index_error = index_error
        self.search_error = search_error
        self.lookup_error = lookup_error
        self.indexed_chunks: list[RagChunk] = []
        self.lookup_calls: list[tuple[str, tuple[str, ...]]] = []
        self.delete_calls: list[tuple[str, tuple[str, ...]]] = []
        self.delete_tenant_calls: list[str] = []
        self.deleted_count = deleted_count

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        self.events.append(f"index:{self.backend_name}")
        if self.index_error is not None:
            raise self.index_error
        self.indexed_chunks.extend(chunks)
        return RagIndexWriteResult(
            indexed_count=len(chunks),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in chunks],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        del search_request
        if self.search_error is not None:
            raise self.search_error
        return list(self.search_results)

    def fetch_by_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> list[Evidence]:
        self.lookup_calls.append((tenant_id, tuple(evidence_ids)))
        if self.lookup_error is not None:
            raise self.lookup_error
        return [
            self.exact_results[evidence_id]
            for evidence_id in evidence_ids
            if evidence_id in self.exact_results
        ]

    def delete_evidence_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> int:
        self.delete_calls.append((tenant_id, tuple(evidence_ids)))
        return self.deleted_count

    def delete_tenant(self, *, tenant_id: str) -> int:
        self.delete_tenant_calls.append(tenant_id)
        original = len(self.indexed_chunks)
        self.indexed_chunks = [
            chunk for chunk in self.indexed_chunks if chunk.tenant_id != tenant_id
        ]
        return original - len(self.indexed_chunks)


class RecordingRevisionLocks:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.lock_batches: list[list[str]] = []

    @contextmanager
    def hold(self, lock_keys: Sequence[str]) -> Iterator[None]:
        self.lock_batches.append(list(lock_keys))
        self.events.append("lock-enter")
        try:
            yield
        finally:
            self.events.append("lock-exit")


class AllowingTenantWriteFence:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def assert_writable(self, tenant_ids: Sequence[str]) -> None:
        self.calls.append(tuple(tenant_ids))


class RecordingTenantWriteFence(AllowingTenantWriteFence):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self._events = events

    def assert_writable(self, tenant_ids: Sequence[str]) -> None:
        super().assert_writable(tenant_ids)
        self._events.append("tenant-fence")


def _persistent_evidence(
    evidence_id: str,
    *,
    content: str,
    ranker: str,
    score: float | None,
    tenant_id: str = "tenant-a",
    source_ref: str = "policy-a",
    metadata: dict[str, object] | None = None,
    retrieved_at: datetime | None = None,
) -> Evidence:
    freshness = Freshness(
        retrieved_at=retrieved_at or datetime(2026, 1, 1, tzinfo=timezone.utc),
        staleness_class=StalenessClass.FRESH,
    )
    return Evidence(
        evidence_id=evidence_id,
        kind=EvidenceKind.DOCUMENT_CHUNK,
        source_ref=source_ref,
        content=content,
        authority=Authority.INTERNAL,
        freshness=freshness,
        structured_content={
            "metadata": metadata or {"department": "hr"},
            "retrieval": {
                "claim_id": "clm_remote",
                "ranker": ranker,
                "score": score,
                "tenant_id": tenant_id,
                "tenant_scoped": True,
            },
        },
    )


def _search_request(*, max_results: int = 3) -> RagSearchRequest:
    return RagSearchRequest(
        tenant_id="tenant-a",
        claim_id="clm_remote",
        query_text="policy",
        max_results=max_results,
    )


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
        reconciliation_response: Mapping[str, object] | None = None,
        deletion_response: Mapping[str, object] | None = None,
        count_response: Mapping[str, object] | None = None,
        health_response: Mapping[str, object] | None = None,
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
        self._search_response = (
            search_response if search_response is not None else {"hits": {"hits": []}}
        )
        self._bulk_response = bulk_response if bulk_response is not None else {"errors": False}
        self._reconciliation_response = (
            reconciliation_response
            if reconciliation_response is not None
            else {
                "timed_out": False,
                "version_conflicts": 0,
                "failures": [],
            }
        )
        self._deletion_response = deletion_response
        self._count_response = count_response if count_response is not None else {"count": 0}
        self._health_response = (
            health_response
            if health_response is not None
            else {
                "status": "green",
                "timed_out": False,
                "number_of_data_nodes": 1,
            }
        )

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
        if path == "/_cluster/health":
            return self._health_response
        if path.endswith("/_count"):
            return self._count_response
        if "_delete_by_query" in path:
            if self._deletion_response is not None:
                return self._deletion_response
            return self._reconciliation_response
        return self._bulk_response


class RecordingPgVectorConnection:
    def __init__(self, rows: Sequence[Mapping[str, object]] = ()) -> None:
        self.execute_many_calls: list[tuple[str, Sequence[Sequence[object]]]] = []
        self.transaction_calls: list[
            Sequence[tuple[str, Sequence[Sequence[object]]]]
        ] = []
        self.fetch_all_calls: list[tuple[str, Sequence[object]]] = []
        self._rows = list(rows)

    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        self.execute_many_calls.append((statement, parameters))

    def execute_many_transactionally(
        self,
        operations: Sequence[tuple[str, Sequence[Sequence[object]]]],
    ) -> None:
        self.transaction_calls.append(operations)

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
        freshness=Freshness(
            retrieved_at=TEST_RETRIEVED_AT,
            staleness_class=StalenessClass.FRESH,
        ),
        metadata={"department": "hr"},
        document_index=1,
        chunk_index=1,
    )


def _valid_opensearch_source() -> dict[str, object]:
    return {
        "tenant_id": "tenant-a",
        "evidence_id": "ev_a",
        "source_ref": "policy-a",
        "content": "Remote work needs manager approval.",
        "authority": "internal",
        "metadata": {"department": "hr"},
        "freshness": {
            "retrieved_at": "2026-01-01T00:00:00+00:00",
            "published_at": None,
            "staleness_class": "fresh",
        },
    }


def _valid_pgvector_row() -> dict[str, object]:
    return {
        "tenant_id": "tenant-a",
        "evidence_id": "ev_pg",
        "source_ref": "policy-a",
        "content": "Remote work needs manager approval.",
        "authority": "internal",
        "staleness_class": "fresh",
        "retrieved_at": TEST_RETRIEVED_AT,
        "published_at": None,
        "metadata": {"department": "hr"},
        "vector_score": 1.0,
    }


def _opensearch_template() -> dict[str, object]:
    return {
        "index_patterns": ["hallu_evidence*"],
        "template": {
            "settings": {"number_of_replicas": 1},
            "mappings": {
                "_meta": {"schema_version": "rag-opensearch-template.v3"},
                "dynamic": False,
                "properties": {
                    "tenant_id": {"type": "keyword"},
                    "evidence_id": {"type": "keyword"},
                    "source_ref": {"type": "keyword"},
                    "corpus_id": {"type": "keyword"},
                    "document_revision": {"type": "keyword"},
                    "content": {"type": "text"},
                    "metadata": {
                        "type": "object",
                        "enabled": False,
                    },
                    "metadata_filter_tokens": {"type": "keyword"},
                },
            },
        },
        "_meta": {
            "schema_version": "rag-opensearch-template.v3",
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
