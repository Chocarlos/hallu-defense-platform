from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from hallu_defense.domain.models import Authority, Freshness, StalenessClass
from hallu_defense.domain.rag_metadata import (
    RagMetadataValidationError,
    validate_metadata,
    validate_persistable_text,
)
from hallu_defense.services.postgres import SqlConnectionProvider
from hallu_defense.services.rag_index import (
    RagChunk,
    RagIndexBackend,
    StorageIdentities,
)

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class RagBackfillError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReindexCorpusResult:
    tenant_id: str
    corpus_id: str
    backend: str
    indexed_count: int
    page_count: int


class RagBackfillSource(Protocol):
    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Iterator[Sequence[RagChunk]]:
        ...


class PgVectorRagBackfillSource:
    backend_name = "pgvector"

    def __init__(self, *, table_name: str, connection: SqlConnectionProvider) -> None:
        _validate_identifier(table_name, "pgvector table name")
        self._table_name = table_name
        self._connection = connection

    @property
    def storage_identities(self) -> StorageIdentities:
        return frozenset({(self.backend_name, self._table_name)})

    def iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Iterator[Sequence[RagChunk]]:
        if page_size <= 0:
            raise RagBackfillError("page_size must be positive.")
        return self._iter_corpus_chunk_pages(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            page_size=page_size,
        )

    def _iter_corpus_chunk_pages(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> Iterator[Sequence[RagChunk]]:
        after_evidence_id = ""
        while True:
            rows = self._connection.fetch_all(
                (
                    "SELECT tenant_id, evidence_id, source_ref, content, authority, "
                    "staleness_class, retrieved_at, published_at, metadata "
                    f"FROM {self._table_name} "
                    "WHERE tenant_id = %s AND metadata @> %s::jsonb "
                    "AND evidence_id > %s "
                    "ORDER BY evidence_id ASC "
                    "LIMIT %s"
                ),
                (
                    tenant_id,
                    json.dumps({"corpus_id": corpus_id}, sort_keys=True),
                    after_evidence_id,
                    page_size,
                ),
            )
            if not rows:
                break
            if len(rows) > page_size:
                raise RagBackfillError("Backfill source returned more rows than requested.")
            page = [_chunk_from_row(row, tenant_id=tenant_id) for row in rows]
            next_evidence_id = page[-1].evidence_id
            if any(chunk.evidence_id <= after_evidence_id for chunk in page):
                raise RagBackfillError("Backfill source keyset cursor did not advance.")
            if any(
                left.evidence_id >= right.evidence_id
                for left, right in zip(page, page[1:], strict=False)
            ):
                raise RagBackfillError("Backfill source page is not in stable keyset order.")
            yield page
            if len(rows) < page_size:
                break
            after_evidence_id = next_evidence_id


class RagCorpusReindexer:
    def __init__(self, *, source: RagBackfillSource, target: RagIndexBackend) -> None:
        self._source = source
        self._target = target
        self._source_identities = _declared_storage_identities(source)
        self._target_identities = _declared_storage_identities(target)
        self._target_backfill_page_safe = getattr(target, "backfill_page_safe", None) is True

    def reindex_corpus(
        self,
        *,
        tenant_id: str,
        corpus_id: str,
        page_size: int,
    ) -> ReindexCorpusResult:
        validate_backfill_storage_identities(
            source_identities=self._source_identities,
            target_identities=self._target_identities,
            target_backfill_page_safe=self._target_backfill_page_safe,
        )
        indexed_count = 0
        page_count = 0
        for page in self._source.iter_corpus_chunk_pages(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            page_size=page_size,
        ):
            result = self._target.index_chunks(page)
            indexed_count += result.indexed_count
            page_count += 1
        return ReindexCorpusResult(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            backend=self._target.backend_name,
            indexed_count=indexed_count,
            page_count=page_count,
        )


def validate_backfill_storage_identities(
    *,
    source_identities: StorageIdentities | None,
    target_identities: StorageIdentities | None,
    target_backfill_page_safe: bool,
) -> None:
    if not source_identities or not target_identities:
        raise RagBackfillError(
            "RAG backfill requires explicit source and target storage identities."
        )
    if source_identities & target_identities:
        raise RagBackfillError(
            "RAG backfill source and target resolve to the same pgvector storage "
            "or another overlapping persistent storage."
        )
    if target_backfill_page_safe is not True:
        raise RagBackfillError(
            "RAG backfill target does not declare page-safe writes; reindexing is "
            "disabled until a generational backfill protocol is configured."
        )


def _declared_storage_identities(component: object) -> StorageIdentities | None:
    identities = getattr(component, "storage_identities", None)
    if not isinstance(identities, frozenset) or not identities:
        return None
    for identity in identities:
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or not all(isinstance(part, str) and part.strip() for part in identity)
        ):
            return None
    return identities


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
            retrieved_at=_required_datetime(row.get("retrieved_at"), "retrieved_at"),
            published_at=_published_at(row.get("published_at")),
            staleness_class=_staleness(row.get("staleness_class")),
        ),
        metadata=_metadata(row.get("metadata")),
    )


def _metadata(value: object) -> dict[str, object]:
    try:
        if isinstance(value, Mapping):
            return dict(validate_metadata(value))
        if isinstance(value, str):
            decoded = json.loads(value)
            if isinstance(decoded, Mapping):
                return dict(validate_metadata(decoded))
    except (json.JSONDecodeError, RagMetadataValidationError, TypeError, ValueError):
        pass
    raise RagBackfillError("Backfill source metadata must be a JSON object.")


def _authority(value: object) -> Authority:
    if isinstance(value, str):
        try:
            return Authority(value)
        except ValueError:
            pass
    raise RagBackfillError("Backfill source authority is invalid.")


def _staleness(value: object) -> StalenessClass:
    if isinstance(value, str):
        try:
            return StalenessClass(value)
        except ValueError:
            pass
    raise RagBackfillError("Backfill source staleness_class is invalid.")


def _published_at(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime) and value.utcoffset() is not None:
        return value
    raise RagBackfillError("Backfill source published_at must be timezone-aware or null.")


def _required_datetime(value: object, field_name: str) -> datetime:
    if isinstance(value, datetime) and value.utcoffset() is not None:
        return value
    raise RagBackfillError(f"Backfill source row missing timezone-aware {field_name}.")


def _required_string(value: object, field_name: str) -> str:
    if isinstance(value, str) and value.strip():
        try:
            return validate_persistable_text(value)
        except RagMetadataValidationError:
            pass
    raise RagBackfillError(f"Backfill source row missing non-empty {field_name}.")


def _validate_identifier(value: str, label: str) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise RagBackfillError(f"{label} must be a safe SQL identifier.")
