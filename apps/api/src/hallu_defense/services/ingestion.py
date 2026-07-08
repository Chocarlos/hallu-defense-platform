from __future__ import annotations

from hallu_defense.domain.models import (
    DocumentIngestionRequest,
    DocumentIngestionResponse,
)
from hallu_defense.services.rag_access import RagAccessPolicy
from hallu_defense.services.retrieval import HybridRetriever


class DocumentIngestionService:
    def __init__(
        self,
        retriever: HybridRetriever,
        access_policy: RagAccessPolicy | None = None,
    ) -> None:
        self._retriever = retriever
        self._access_policy = access_policy or RagAccessPolicy()

    def ingest(
        self,
        request: DocumentIngestionRequest,
        *,
        tenant_id: str,
        trace_id: str,
        principal_roles: frozenset[str] = frozenset(),
    ) -> DocumentIngestionResponse:
        documents = [
            self._access_policy.stamp_document_metadata(
                document,
                tenant_id=tenant_id,
                corpus_id=request.corpus_id,
                principal_roles=principal_roles,
            )
            for document in request.documents
        ]
        result = self._retriever.index_documents(tenant_id=tenant_id, documents=documents)
        warnings: list[str] = []
        if result.backend == "local":
            warnings.append(
                "No persistent RAG index backend is configured; documents were validated but not persisted."
            )
        return DocumentIngestionResponse(
            trace_id=trace_id,
            tenant_id=tenant_id,
            corpus_id=request.corpus_id,
            backend=result.backend,
            document_count=len(request.documents),
            indexed_count=result.indexed_count,
            evidence_ids=result.evidence_ids,
            warnings=warnings,
        )
