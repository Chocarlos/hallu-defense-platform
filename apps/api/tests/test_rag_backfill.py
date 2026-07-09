from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

import pytest

from hallu_defense.domain.models import Authority, Freshness, StalenessClass
from hallu_defense.services.postgres import RecordingSqlProvider
from hallu_defense.services.rag_backfill import (
    PgVectorRagBackfillSource,
    RagBackfillError,
    RagCorpusReindexer,
)
from hallu_defense.services.rag_index import RagChunk, RagIndexWriteResult


def test_pgvector_backfill_source_reads_tenant_corpus_pages() -> None:
    provider = RecordingSqlProvider(
        fetch_all_rows=[
            {
                "tenant_id": "tenant-a",
                "evidence_id": "ev_1",
                "source_ref": "policy-a",
                "content": "Remote work needs approval.",
                "authority": "internal",
                "staleness_class": "fresh",
                "published_at": datetime(2026, 7, 1, tzinfo=timezone.utc),
                "metadata": json.dumps({"corpus_id": "hr", "department": "hr"}),
            }
        ]
    )
    source = PgVectorRagBackfillSource(table_name="rag_evidence_chunks", connection=provider)

    pages = source.iter_corpus_chunk_pages(tenant_id="tenant-a", corpus_id="hr", page_size=50)

    assert len(pages) == 1
    chunk = pages[0][0]
    assert chunk.tenant_id == "tenant-a"
    assert chunk.evidence_id == "ev_1"
    assert chunk.metadata == {"corpus_id": "hr", "department": "hr"}
    statement = provider.calls[0][1]
    parameters = provider.calls[0][2]
    assert "metadata @> %s::jsonb" in statement
    assert "LIMIT %s OFFSET %s" in statement
    assert parameters == ("tenant-a", '{"corpus_id": "hr"}', 50, 0)


def test_pgvector_backfill_source_rejects_cross_tenant_rows() -> None:
    source = PgVectorRagBackfillSource(
        table_name="rag_evidence_chunks",
        connection=RecordingSqlProvider(
            fetch_all_rows=[
                {
                    "tenant_id": "tenant-b",
                    "evidence_id": "ev_1",
                    "source_ref": "policy-a",
                    "content": "Wrong tenant.",
                    "authority": "internal",
                    "staleness_class": "fresh",
                    "metadata": {"corpus_id": "hr"},
                }
            ]
        ),
    )

    with pytest.raises(RagBackfillError, match="another tenant"):
        source.iter_corpus_chunk_pages(tenant_id="tenant-a", corpus_id="hr", page_size=50)


def test_reindexer_reuses_stable_evidence_ids_for_idempotent_upsert() -> None:
    source = RecordingBackfillSource(
        pages=[
            [
                RagChunk(
                    tenant_id="tenant-a",
                    evidence_id="ev_stable",
                    source_ref="policy-a",
                    content="Remote work needs approval.",
                    authority=Authority.INTERNAL,
                    freshness=Freshness(staleness_class=StalenessClass.FRESH),
                    metadata={"corpus_id": "hr"},
                )
            ]
        ]
    )
    target = RecordingRagIndexBackend()
    reindexer = RagCorpusReindexer(source=source, target=target)

    first = reindexer.reindex_corpus(tenant_id="tenant-a", corpus_id="hr", page_size=10)
    second = reindexer.reindex_corpus(tenant_id="tenant-a", corpus_id="hr", page_size=10)

    assert first.evidence_ids == ["ev_stable"]
    assert second.evidence_ids == ["ev_stable"]
    assert [chunk.evidence_id for page in target.pages for chunk in page] == [
        "ev_stable",
        "ev_stable",
    ]


class RecordingBackfillSource:
    def __init__(self, *, pages: Sequence[Sequence[RagChunk]]) -> None:
        self.pages = [list(page) for page in pages]
        self.calls: list[tuple[str, str, int]] = []

    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Sequence[Sequence[RagChunk]]:
        self.calls.append((tenant_id, corpus_id, page_size))
        return self.pages


class RecordingRagIndexBackend:
    backend_name = "recording"

    def __init__(self) -> None:
        self.pages: list[list[RagChunk]] = []

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        page = list(chunks)
        self.pages.append(page)
        return RagIndexWriteResult(
            indexed_count=len(page),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in page],
        )

    def search(self, search_request: Mapping[str, object]) -> list[object]:
        del search_request
        return []
