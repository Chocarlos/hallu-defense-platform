from __future__ import annotations

from collections.abc import Sequence

from hallu_defense.domain.models import (
    DocumentInput,
    DocumentIngestionRequest,
    DocumentIngestionResponse,
)
from hallu_defense.domain.rag_metadata import RagMetadataValidationError, validate_metadata
from hallu_defense.services.rag_access import RagAccessDeniedError, RagAccessPolicy
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
        documents = self.prepare_documents(
            request,
            tenant_id=tenant_id,
            principal_roles=principal_roles,
        )
        return self.ingest_prepared(
            documents,
            corpus_id=request.corpus_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            document_count=len(request.documents),
        )

    def prepare_documents(
        self,
        request: DocumentIngestionRequest,
        *,
        tenant_id: str,
        principal_roles: frozenset[str] = frozenset(),
    ) -> list[DocumentInput]:
        return [
            self._access_policy.stamp_document_metadata(
                document,
                tenant_id=tenant_id,
                corpus_id=request.corpus_id,
                principal_roles=principal_roles,
            )
            for document in request.documents
        ]

    def ingest_prepared(
        self,
        documents: Sequence[DocumentInput],
        *,
        corpus_id: str,
        tenant_id: str,
        trace_id: str,
        document_count: int | None = None,
    ) -> DocumentIngestionResponse:
        self._validate_prepared_documents(
            documents,
            corpus_id=corpus_id,
            tenant_id=tenant_id,
        )
        result = self._retriever.index_documents(tenant_id=tenant_id, documents=list(documents))
        warnings: list[str] = []
        if result.backend == "local":
            warnings.append(
                "No persistent RAG index backend is configured; documents were validated but not persisted."
            )
        return DocumentIngestionResponse(
            trace_id=trace_id,
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            backend=result.backend,
            document_count=document_count if document_count is not None else len(documents),
            indexed_count=result.indexed_count,
            evidence_ids=result.evidence_ids,
            warnings=warnings,
        )

    def _validate_prepared_documents(
        self,
        documents: Sequence[DocumentInput],
        *,
        corpus_id: str,
        tenant_id: str,
    ) -> None:
        for document in documents:
            try:
                validate_metadata(document.metadata)
            except RagMetadataValidationError as exc:
                raise RagAccessDeniedError(str(exc)) from None
            if document.metadata.get("corpus_id") != corpus_id:
                raise RagAccessDeniedError(
                    "Prepared RAG metadata corpus_id must match the ingestion request."
                )
            if document.metadata.get("owner_tenant_id") != tenant_id:
                raise RagAccessDeniedError(
                    "Prepared RAG metadata owner_tenant_id must match the authenticated tenant."
                )
