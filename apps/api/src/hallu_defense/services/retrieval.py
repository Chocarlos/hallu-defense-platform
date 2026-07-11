from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from hallu_defense.domain.models import (
    Authority,
    Claim,
    DocumentInput,
    Evidence,
    EvidenceKind,
    Freshness,
    StalenessClass,
)
from hallu_defense.domain.rag_metadata import (
    RagMetadataValidationError,
    canonical_json,
    metadata_values_equal,
    validate_metadata,
    validate_metadata_filter,
)
from hallu_defense.services.content_security import ContentSecurityScanner
from hallu_defense.services.rag_index import (
    CORPUS_ID_METADATA_KEY,
    DOCUMENT_REVISION_METADATA_KEY,
    RagChunk,
    RagIndexBackend,
    RagIndexConfigurationError,
    RagIndexWriteResult,
    RagSearchRequest,
)
from hallu_defense.services.text import normalize_text, tokenize

AUTHORITY_SCORE = {
    Authority.OFFICIAL: 1.0,
    Authority.INTERNAL: 0.85,
    Authority.TRUSTED_THIRD_PARTY: 0.7,
    Authority.UNKNOWN: 0.35,
}

FRESHNESS_SCORE = {
    StalenessClass.FRESH: 1.0,
    StalenessClass.ACCEPTABLE: 0.75,
    StalenessClass.STALE: 0.2,
    StalenessClass.UNKNOWN: 0.4,
}

SECTION_METADATA_PREFIX = "structural_"


@dataclass(frozen=True)
class DocumentChunk:
    content: str
    section_path: tuple[str, ...] = ()
    section_level: int = 0

    @property
    def has_section(self) -> bool:
        return bool(self.section_path)


class HybridRetriever:
    def __init__(
        self,
        index_backend: RagIndexBackend | None = None,
        content_scanner: ContentSecurityScanner | None = None,
    ) -> None:
        self._index_backend = index_backend
        self._content_scanner = content_scanner or ContentSecurityScanner()

    def index_documents(
        self,
        *,
        tenant_id: str,
        documents: list[DocumentInput],
    ) -> RagIndexWriteResult:
        if self._index_backend is None:
            return RagIndexWriteResult(indexed_count=0, backend="local")
        chunks = self._chunk_documents(documents)
        return self._index_backend.index_chunks(
            [
                self._chunk_to_rag_chunk(
                    tenant_id=tenant_id,
                    evidence=evidence,
                )
                for evidence in chunks
            ]
        )

    def retrieve(
        self,
        claims: list[Claim],
        documents: list[DocumentInput],
        max_evidence_per_claim: int = 3,
        metadata_filter: dict[str, object] | None = None,
        tenant_id: str | None = None,
        context_refs: list[str] | None = None,
    ) -> tuple[list[Evidence], dict[str, list[str]]]:
        chunks = list(self._chunk_documents(documents))
        try:
            filters = dict(validate_metadata_filter(metadata_filter or {}))
        except RagMetadataValidationError as exc:
            raise RagIndexConfigurationError(str(exc)) from None
        refs = context_refs or []
        filtered_chunks = [
            evidence
            for evidence in chunks
            if self._metadata_matches(self._metadata_for(evidence), filters)
        ]
        claim_map: dict[str, list[str]] = {}
        selected_evidence: list[Evidence] = []
        selected_ids: set[str] = set()

        for claim in claims:
            persistent = self._persistent_search(
                claim=claim,
                tenant_id=tenant_id,
                metadata_filter=filters,
                context_refs=refs,
                max_evidence_per_claim=max_evidence_per_claim,
            )
            ranked = [*persistent, *self._rank(claim, filtered_chunks)]
            selected = ranked[:max_evidence_per_claim]
            claim_map[claim.claim_id] = [evidence.evidence_id for evidence in selected]
            for evidence in selected:
                if evidence.evidence_id not in selected_ids:
                    selected_ids.add(evidence.evidence_id)
                    selected_evidence.append(evidence)

        return selected_evidence, claim_map

    def _persistent_search(
        self,
        *,
        claim: Claim,
        tenant_id: str | None,
        metadata_filter: Mapping[str, object],
        context_refs: list[str],
        max_evidence_per_claim: int,
    ) -> list[Evidence]:
        if self._index_backend is None:
            return []
        if tenant_id is None or not tenant_id.strip():
            raise ValueError("tenant_id is required for persistent RAG retrieval")
        return self._index_backend.search(
            RagSearchRequest(
                tenant_id=tenant_id,
                claim_id=claim.claim_id,
                query_text=claim.text,
                metadata_filter=metadata_filter,
                context_refs=context_refs,
                max_results=max_evidence_per_claim,
            )
        )

    def _chunk_documents(self, documents: list[DocumentInput]) -> list[Evidence]:
        chunks: list[Evidence] = []
        for document_index, document in enumerate(documents, start=1):
            document_revision = self._document_revision(document)
            retrieved_at = datetime.now(timezone.utc)
            for chunk_index, chunk in enumerate(self._split_document(document.content), start=1):
                metadata = self._chunk_metadata(
                    document.metadata,
                    chunk,
                    document_revision=document_revision,
                )
                structured_content: dict[str, object] = {
                    "metadata": metadata,
                    "document_index": document_index,
                    "chunk_index": chunk_index,
                }
                if chunk.has_section:
                    structured_content["structure"] = self._structure_trace(chunk)
                chunks.append(
                    self._content_scanner.mark_evidence(
                        Evidence(
                            evidence_id=f"ev_{document_index:03d}_{chunk_index:03d}",
                            kind=EvidenceKind.DOCUMENT_CHUNK,
                            source_ref=document.source_ref,
                            content=chunk.content,
                            authority=document.authority,
                            freshness=self._freshness_from_metadata(
                                metadata,
                                retrieved_at=retrieved_at,
                            ),
                            structured_content=structured_content,
                        )
                    )
                )
        return chunks

    def _split_document(self, content: str) -> list[DocumentChunk]:
        section_chunks = self._split_markdown_sections(content)
        if section_chunks:
            return section_chunks
        paragraphs = [part.strip() for part in content.split("\n\n") if part.strip()]
        if not paragraphs:
            paragraphs = [content]
        return [DocumentChunk(content=paragraph) for paragraph in paragraphs]

    def _split_markdown_sections(self, content: str) -> list[DocumentChunk]:
        chunks: list[DocumentChunk] = []
        section_stack: list[str] = []
        section_level = 0
        block_lines: list[str] = []
        saw_heading = False

        for raw_line in content.splitlines():
            heading = self._parse_markdown_heading(raw_line)
            if heading is not None:
                saw_heading = True
                self._append_structured_blocks(
                    chunks,
                    block_lines,
                    section_path=tuple(section_stack),
                    section_level=section_level,
                )
                level, title = heading
                section_stack = [*section_stack[: level - 1], title]
                section_level = level
                block_lines = []
                continue
            block_lines.append(raw_line)

        self._append_structured_blocks(
            chunks,
            block_lines,
            section_path=tuple(section_stack),
            section_level=section_level,
        )
        if not saw_heading:
            return []
        if not chunks and section_stack:
            chunks.append(
                DocumentChunk(
                    content=section_stack[-1],
                    section_path=tuple(section_stack),
                    section_level=section_level,
                )
            )
        return chunks

    def _append_structured_blocks(
        self,
        chunks: list[DocumentChunk],
        lines: list[str],
        *,
        section_path: tuple[str, ...],
        section_level: int,
    ) -> None:
        blocks = [part.strip() for part in "\n".join(lines).split("\n\n") if part.strip()]
        for block in blocks:
            content = self._section_content(block, section_path)
            chunks.append(
                DocumentChunk(
                    content=content,
                    section_path=section_path,
                    section_level=section_level if section_path else 0,
                )
            )

    def _parse_markdown_heading(self, line: str) -> tuple[int, str] | None:
        stripped = line.strip()
        if not stripped.startswith("#"):
            return None
        marker_count = len(stripped) - len(stripped.lstrip("#"))
        if marker_count > 6:
            return None
        remainder = stripped[marker_count:]
        if not remainder.startswith(" "):
            return None
        title = remainder.strip().strip("#").strip()
        if not title:
            return None
        return marker_count, title

    def _section_content(self, block: str, section_path: tuple[str, ...]) -> str:
        if not section_path:
            return block
        return f"{section_path[-1]}\n\n{block}"

    def _chunk_metadata(
        self,
        document_metadata: dict[str, object],
        chunk: DocumentChunk,
        *,
        document_revision: str | None,
    ) -> dict[str, object]:
        metadata = dict(document_metadata)
        if document_revision is not None:
            metadata[DOCUMENT_REVISION_METADATA_KEY] = document_revision
        if chunk.has_section:
            metadata.update(self._structure_metadata(chunk))
        try:
            return dict(validate_metadata(metadata))
        except RagMetadataValidationError as exc:
            raise RagIndexConfigurationError(str(exc)) from None

    def _document_revision(self, document: DocumentInput) -> str | None:
        corpus_id = document.metadata.get(CORPUS_ID_METADATA_KEY)
        if not isinstance(corpus_id, str) or not corpus_id.strip():
            return None
        supplied_revision = document.metadata.get(DOCUMENT_REVISION_METADATA_KEY)
        if isinstance(supplied_revision, str) and supplied_revision.strip():
            return supplied_revision
        metadata = {
            key: value
            for key, value in document.metadata.items()
            if key != DOCUMENT_REVISION_METADATA_KEY
        }
        identity = [
            document.source_ref,
            document.content,
            document.authority.value,
            canonical_json(metadata),
        ]
        encoded = canonical_json(identity)
        return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"

    def _structure_metadata(self, chunk: DocumentChunk) -> dict[str, object]:
        return {
            f"{SECTION_METADATA_PREFIX}section_heading": chunk.section_path[-1],
            f"{SECTION_METADATA_PREFIX}section_path": " > ".join(chunk.section_path),
            f"{SECTION_METADATA_PREFIX}section_level": chunk.section_level,
            f"{SECTION_METADATA_PREFIX}chunk_kind": "section",
        }

    def _structure_trace(self, chunk: DocumentChunk) -> dict[str, object]:
        return {
            "section_heading": chunk.section_path[-1],
            "section_path": list(chunk.section_path),
            "section_level": chunk.section_level,
            "chunk_kind": "section",
        }

    def _chunk_to_rag_chunk(self, *, tenant_id: str, evidence: Evidence) -> RagChunk:
        metadata = self._metadata_for(evidence)
        return RagChunk(
            tenant_id=tenant_id,
            evidence_id=self._persistent_evidence_id(evidence, metadata),
            source_ref=evidence.source_ref,
            content=evidence.content,
            authority=evidence.authority,
            freshness=evidence.freshness,
            metadata=metadata,
            document_index=self._int_metadata(evidence, "document_index"),
            chunk_index=self._int_metadata(evidence, "chunk_index"),
        )

    def _persistent_evidence_id(self, evidence: Evidence, metadata: dict[str, object]) -> str:
        identity = {
            "corpus_id": metadata.get("corpus_id", ""),
            "source_ref": evidence.source_ref,
            "document_index": self._int_metadata(evidence, "document_index"),
            "chunk_index": self._int_metadata(evidence, "chunk_index"),
        }
        encoded = canonical_json(identity)
        return f"ev_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"

    def _rank(self, claim: Claim, chunks: list[Evidence]) -> list[Evidence]:
        claim_tokens = tokenize(claim.text)
        if not claim_tokens:
            return []
        evidence_tokens = {evidence.evidence_id: tokenize(evidence.content) for evidence in chunks}
        doc_frequency = self._doc_frequency(evidence_tokens.values(), claim_tokens)
        scored: list[tuple[float, str, Evidence]] = []

        for evidence in chunks:
            scores = self._score(
                claim.text,
                claim_tokens,
                evidence,
                evidence_tokens[evidence.evidence_id],
                doc_frequency,
                len(chunks),
            )
            content_score = self._numeric_score(scores, "content_score")
            total_score = self._numeric_score(scores, "total_score")
            if content_score <= 0.08:
                continue
            scored.append(
                (
                    total_score,
                    evidence.evidence_id,
                    self._with_retrieval_trace(evidence, claim.claim_id, scores),
                )
            )

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [evidence for _score, _evidence_id, evidence in scored]

    def _score(
        self,
        claim_text: str,
        claim_tokens: set[str],
        evidence: Evidence,
        evidence_tokens: set[str],
        doc_frequency: dict[str, int],
        document_count: int,
    ) -> dict[str, object]:
        overlap = claim_tokens.intersection(evidence_tokens)
        weighted_overlap = sum(self._idf(token, doc_frequency, document_count) for token in overlap)
        weighted_claim = sum(self._idf(token, doc_frequency, document_count) for token in claim_tokens)
        weighted_coverage = weighted_overlap / max(weighted_claim, 1e-9)
        density = len(overlap) / max(len(evidence_tokens), 1)
        bm25_score = min(1.0, (0.75 * weighted_coverage) + (0.25 * density))
        vector_score = len(overlap) / math.sqrt(max(len(claim_tokens), 1) * max(len(evidence_tokens), 1))
        content_score = min(1.0, (0.65 * bm25_score) + (0.35 * vector_score))
        authority_score = AUTHORITY_SCORE[evidence.authority]
        freshness_score = FRESHNESS_SCORE[evidence.freshness.staleness_class]
        exact_phrase_bonus = 0.05 if normalize_text(claim_text) in normalize_text(evidence.content) else 0
        total_score = min(
            1.0,
            (0.70 * content_score)
            + (0.18 * authority_score)
            + (0.12 * freshness_score)
            + exact_phrase_bonus,
        )
        return {
            "bm25_score": round(bm25_score, 4),
            "vector_score": round(vector_score, 4),
            "content_score": round(content_score, 4),
            "authority_score": round(authority_score, 4),
            "freshness_score": round(freshness_score, 4),
            "total_score": round(total_score, 4),
            "overlap_terms": sorted(overlap),
        }

    def _with_retrieval_trace(
        self, evidence: Evidence, claim_id: str, scores: dict[str, object]
    ) -> Evidence:
        return evidence.model_copy(
            update={
                "structured_content": {
                    **evidence.structured_content,
                    "retrieval": {
                        "claim_id": claim_id,
                        "ranker": "local_hybrid_v1",
                        **scores,
                    },
                }
            }
        )

    def _numeric_score(self, scores: dict[str, object], key: str) -> float:
        value = scores[key]
        if isinstance(value, int | float):
            return float(value)
        raise TypeError(f"Retrieval score '{key}' must be numeric.")

    def _doc_frequency(
        self, token_sets: Iterable[set[str]], claim_tokens: set[str]
    ) -> dict[str, int]:
        frequencies = {token: 0 for token in claim_tokens}
        for tokens in token_sets:
            for token in claim_tokens:
                if token in tokens:
                    frequencies[token] += 1
        return frequencies

    def _idf(self, token: str, doc_frequency: dict[str, int], document_count: int) -> float:
        frequency = doc_frequency.get(token, 0)
        return math.log((document_count + 1) / (frequency + 0.5)) + 1

    def _metadata_for(self, evidence: Evidence) -> dict[str, object]:
        metadata = evidence.structured_content.get("metadata")
        if isinstance(metadata, dict):
            return metadata
        return {}

    def _int_metadata(self, evidence: Evidence, key: str) -> int:
        value = evidence.structured_content.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return 0

    def _metadata_matches(
        self, metadata: dict[str, object], filters: Mapping[str, object]
    ) -> bool:
        for key, expected in filters.items():
            if key not in metadata:
                return False
            actual = metadata[key]
            if not self._metadata_value_matches(actual, expected):
                return False
        return True

    def _metadata_value_matches(self, actual: object, expected: object) -> bool:
        return metadata_values_equal(actual, expected)

    def _freshness_from_metadata(
        self,
        metadata: dict[str, object],
        *,
        retrieved_at: datetime,
    ) -> Freshness:
        published_at = self._parse_datetime(metadata.get("published_at"))
        staleness = self._explicit_staleness(metadata.get("staleness_class"))
        if staleness is None and published_at is not None:
            age_days = (retrieved_at - published_at).days
            if age_days <= 90:
                staleness = StalenessClass.FRESH
            elif age_days <= 730:
                staleness = StalenessClass.ACCEPTABLE
            else:
                staleness = StalenessClass.STALE
        return Freshness(
            retrieved_at=retrieved_at,
            published_at=published_at,
            staleness_class=staleness or StalenessClass.UNKNOWN,
        )

    def _explicit_staleness(self, value: object) -> StalenessClass | None:
        if isinstance(value, str):
            try:
                return StalenessClass(value)
            except ValueError:
                return None
        return None

    def _parse_datetime(self, value: object) -> datetime | None:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        else:
            return None

        if parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc)
