from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from hallu_defense.domain.models import Authority, Freshness, StalenessClass
from hallu_defense.services.postgres import SqlConnectionProvider
from hallu_defense.services.rag_index import RagChunk, RagIndexBackend

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class RagBackfillError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReindexCorpusResult:
    tenant_id: str
    corpus_id: str
    backend: str
    indexed_count: int
    evidence_ids: list[str]


class RagBackfillSource(Protocol):
    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Sequence[Sequence[RagChunk]]:
        ...


class PgVectorRagBackfillSource:
    def __init__(self, *, table_name: str, connection: SqlConnectionProvider) -> None:
        _validate_identifier(table_name, "pgvector table name")
        self._table_name = table_name
        self._connection = connection

    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Sequence[Sequence[RagChunk]]:
        if page_size <= 0:
            raise RagBackfillError("page_size must be positive.")
        pages: list[list[RagChunk]] = []
        offset = 0
        while True:
            rows = self._connection.fetch_all(
                (
                    "SELECT tenant_id, evidence_id, source_ref, content, authority, "
                    "staleness_class, published_at, metadata "
                    f"FROM {self._table_name} "
                    "WHERE tenant_id = %s AND metadata @> %s::jsonb "
                    "ORDER BY source_ref ASC, evidence_id ASC "
                    "LIMIT %s OFFSET %s"
                ),
                (
                    tenant_id,
                    json.dumps({"corpus_id": corpus_id}, sort_keys=True),
                    page_size,
                    offset,
                ),
            )
            if not rows:
                break
            pages.append([_chunk_from_row(row, tenant_id=tenant_id) for row in rows])
            if len(rows) < page_size:
                break
            offset += page_size
        return pages


class RagCorpusReindexer:
    def __init__(self, *, source: RagBackfillSource, target: RagIndexBackend) -> None:
        self._source = source
        self._target = target

    def reindex_corpus(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> ReindexCorpusResult:
        indexed_count = 0
        evidence_ids: list[str] = []
        for page in self._source.iter_corpus_chunk_pages(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            page_size=page_size,
        ):
            result = self._target.index_chunks(page)
            indexed_count += result.indexed_count
            evidence_ids.extend(result.evidence_ids)
        return ReindexCorpusResult(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            backend=self._target.backend_name,
            indexed_count=indexed_count,
            evidence_ids=evidence_ids,
        )


def _chunk_from_row(row: Mapping[str, object], *, tenant_id: str) -> RagChunk:
    row_tenant = _required_string(row.get("tenant_id"), "tenant_id")
    if row_tenant != tenant_id:
        raise RagBackfillError("Backfill source returned a row for another tenant.")
    return RagChunk(
        tenant_id=row_tenant,
        evidence_id=_required_string(row.get("evidence_id"), "evidence_id"),
        source_ref=_required_string(row.get("source_ref"), "source_ref"),
        content=_required_string(row.get("content"), "content"),
        authority=_authority(row.get("authority")),
        freshness=Freshness(
            published_at=_published_at(row.get("published_at")),
            staleness_class=_staleness(row.get("staleness_class")),
        ),
        metadata=_metadata(row.get("metadata")),
    )


def _metadata(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        decoded = json.loads(value)
        if isinstance(decoded, Mapping):
            return dict(decoded)
    raise RagBackfillError("Backfill source metadata must be a JSON object.")


def _authority(value: object) -> Authority:
    if isinstance(value, str):
        try:
            return Authority(value)
        except ValueError:
            return Authority.UNKNOWN
    return Authority.UNKNOWN


def _staleness(value: object) -> StalenessClass:
    if isinstance(value, str):
        try:
            return StalenessClass(value)
        except ValueError:
            return StalenessClass.UNKNOWN
    return StalenessClass.UNKNOWN


def _published_at(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    return None


def _required_string(value: object, field_name: str) -> str:
    if isinstance(value, str) and value.strip():
        return value
    raise RagBackfillError(f"Backfill source row missing non-empty {field_name}.")


def _validate_identifier(value: str, label: str) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise RagBackfillError(f"{label} must be a safe SQL identifier.")
