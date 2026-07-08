from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from urllib import error, request

from hallu_defense.config import Settings
from hallu_defense.domain.models import (
    Authority,
    Evidence,
    EvidenceKind,
    Freshness,
    StalenessClass,
)

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRUCTURAL_METADATA_PREFIX = "structural_"


class RagIndexError(RuntimeError):
    pass


class RagIndexConfigurationError(RagIndexError):
    pass


class RagIndexTransportError(RagIndexError):
    pass


@dataclass(frozen=True)
class RagChunk:
    tenant_id: str
    evidence_id: str
    source_ref: str
    content: str
    authority: Authority
    freshness: Freshness
    metadata: Mapping[str, object] = field(default_factory=dict)
    document_index: int = 0
    chunk_index: int = 0


@dataclass(frozen=True)
class RagSearchRequest:
    tenant_id: str
    claim_id: str
    query_text: str
    metadata_filter: Mapping[str, object] = field(default_factory=dict)
    context_refs: Sequence[str] = field(default_factory=tuple)
    max_results: int = 3


@dataclass(frozen=True)
class RagIndexWriteResult:
    indexed_count: int
    backend: str
    evidence_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OpenSearchTemplateInstallResult:
    template_name: str
    path: str
    acknowledged: bool
    response: Mapping[str, object]


class RagIndexBackend(Protocol):
    backend_name: str

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        ...

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        ...


class TextEmbedder(Protocol):
    dimension: int

    def embed(self, text: str) -> list[float]:
        ...


class DeterministicHashEmbedder:
    def __init__(self, dimension: int = 16) -> None:
        if dimension <= 0:
            raise RagIndexConfigurationError("embedding dimension must be positive")
        self.dimension = dimension

    def embed(self, text: str) -> list[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        values: list[float] = []
        for index in range(self.dimension):
            raw = digest[index % len(digest)]
            values.append(round((raw / 255.0) * 2 - 1, 6))
        return values


class OpenSearchTransport(Protocol):
    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        ...


class OpenSearchRagIndexBackend:
    backend_name = "opensearch"

    def __init__(
        self,
        *,
        endpoint: str,
        index_name: str,
        timeout_seconds: float,
        transport: OpenSearchTransport | None = None,
    ) -> None:
        if not endpoint.strip():
            raise RagIndexConfigurationError("OpenSearch endpoint must be configured")
        _validate_identifier(index_name, "OpenSearch index name")
        self._endpoint = endpoint.rstrip("/")
        self._index_name = index_name
        self._timeout_seconds = timeout_seconds
        self._transport = transport or UrlLibOpenSearchTransport(self._endpoint)

    def install_index_template(
        self,
        *,
        template_name: str,
        template: Mapping[str, object],
    ) -> OpenSearchTemplateInstallResult:
        _validate_identifier(template_name, "OpenSearch template name")
        _validate_opensearch_template_payload(template)
        path = f"/_index_template/{template_name}"
        response = self._transport.request_json(
            "PUT",
            path,
            template,
            timeout_seconds=self._timeout_seconds,
        )
        return OpenSearchTemplateInstallResult(
            template_name=template_name,
            path=path,
            acknowledged=response.get("acknowledged") is True,
            response=response,
        )

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        if not chunks:
            return RagIndexWriteResult(indexed_count=0, backend=self.backend_name)
        _ensure_single_tenant(chunks)
        operations: list[object] = []
        for chunk in chunks:
            _validate_tenant_id(chunk.tenant_id)
            operations.append(
                {
                    "index": {
                        "_index": self._index_name,
                        "_id": _opensearch_document_id(chunk.tenant_id, chunk.evidence_id),
                    }
                }
            )
            operations.append(_opensearch_source_from_chunk(chunk))
        self._transport.request_json(
            "POST",
            "/_bulk",
            operations,
            headers={"content-type": "application/x-ndjson"},
            timeout_seconds=self._timeout_seconds,
        )
        return RagIndexWriteResult(
            indexed_count=len(chunks),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in chunks],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        _validate_search_request(search_request)
        filters: list[object] = [{"term": {"tenant_id": search_request.tenant_id}}]
        if search_request.context_refs:
            filters.append({"terms": {"source_ref": list(search_request.context_refs)}})
        for key, value in sorted(search_request.metadata_filter.items()):
            filters.append({"term": {f"metadata.{key}": value}})

        body: dict[str, object] = {
            "size": search_request.max_results,
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": search_request.query_text,
                                "fields": ["content^2", "source_ref", "metadata.*"],
                            }
                        }
                    ],
                    "filter": filters,
                }
            },
        }
        response = self._transport.request_json(
            "POST",
            f"/{self._index_name}/_search",
            body,
            timeout_seconds=self._timeout_seconds,
        )
        return _evidence_from_opensearch_response(response, search_request)


class PgVectorConnection(Protocol):
    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        ...

    def fetch_all(self, statement: str, parameters: Sequence[object]) -> Sequence[Mapping[str, object]]:
        ...


class PgVectorRagIndexBackend:
    backend_name = "pgvector"

    def __init__(
        self,
        *,
        table_name: str,
        connection: PgVectorConnection,
        embedder: TextEmbedder | None = None,
    ) -> None:
        _validate_identifier(table_name, "pgvector table name")
        self._table_name = table_name
        self._connection = connection
        self._embedder = embedder or DeterministicHashEmbedder()

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        if not chunks:
            return RagIndexWriteResult(indexed_count=0, backend=self.backend_name)
        _ensure_single_tenant(chunks)
        statement = (
            f"INSERT INTO {self._table_name} "
            "(tenant_id, evidence_id, source_ref, content, authority, staleness_class, "
            "published_at, metadata, embedding) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::vector) "
            "ON CONFLICT (tenant_id, evidence_id) DO UPDATE SET "
            "source_ref = EXCLUDED.source_ref, content = EXCLUDED.content, "
            "authority = EXCLUDED.authority, staleness_class = EXCLUDED.staleness_class, "
            "published_at = EXCLUDED.published_at, metadata = EXCLUDED.metadata, "
            "embedding = EXCLUDED.embedding"
        )
        parameters = [_pgvector_chunk_parameters(chunk, self._embedder) for chunk in chunks]
        self._connection.execute_many(statement, parameters)
        return RagIndexWriteResult(
            indexed_count=len(chunks),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in chunks],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        _validate_search_request(search_request)
        embedding = self._embedder.embed(search_request.query_text)
        filters = ["tenant_id = %s"]
        filter_parameters: list[object] = [search_request.tenant_id]
        if search_request.context_refs:
            filters.append("source_ref = ANY(%s)")
            filter_parameters.append(list(search_request.context_refs))
        if search_request.metadata_filter:
            filters.append("metadata @> %s::jsonb")
            filter_parameters.append(json.dumps(search_request.metadata_filter, sort_keys=True))
        parameters = [
            *filter_parameters,
            _pgvector_literal(embedding),
            search_request.max_results,
        ]
        statement = (
            "SELECT tenant_id, evidence_id, source_ref, content, authority, staleness_class, "
            f"published_at, metadata FROM {self._table_name} "
            f"WHERE {' AND '.join(filters)} "
            "ORDER BY embedding <=> %s::vector "
            "LIMIT %s"
        )
        rows = self._connection.fetch_all(statement, parameters)
        return [_evidence_from_pgvector_row(row, search_request) for row in rows]


class UrlLibOpenSearchTransport:
    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint.rstrip("/")

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        encoded_body = _encode_opensearch_body(body)
        req = request.Request(
            f"{self._endpoint}{path}",
            data=encoded_body,
            method=method,
            headers=dict(headers or {"content-type": "application/json"}),
        )
        try:
            with request.urlopen(req, timeout=timeout_seconds) as response:
                payload = response.read().decode("utf-8")
        except error.URLError as exc:
            raise RagIndexTransportError(f"OpenSearch request failed: {exc}") from exc
        if not payload.strip():
            return {}
        decoded = json.loads(payload)
        if not isinstance(decoded, Mapping):
            raise RagIndexTransportError("OpenSearch response must be a JSON object")
        return decoded


def create_rag_index_backend(settings: Settings) -> RagIndexBackend | None:
    backend = settings.rag_index_backend.strip().lower()
    if backend == "local":
        return None
    if backend == "opensearch":
        return OpenSearchRagIndexBackend(
            endpoint=settings.opensearch_endpoint,
            index_name=settings.opensearch_index_name,
            timeout_seconds=settings.rag_index_timeout_seconds,
        )
    if backend == "pgvector":
        raise RagIndexConfigurationError(
            "pgvector backend requires an injected PgVectorConnection; runtime wiring is pending."
        )
    raise RagIndexConfigurationError(f"Unsupported RAG index backend: {settings.rag_index_backend}")


def _opensearch_source_from_chunk(chunk: RagChunk) -> dict[str, object]:
    return {
        "tenant_id": chunk.tenant_id,
        "evidence_id": chunk.evidence_id,
        "source_ref": chunk.source_ref,
        "content": chunk.content,
        "authority": chunk.authority.value,
        "freshness": {
            "retrieved_at": chunk.freshness.retrieved_at.isoformat(),
            "published_at": chunk.freshness.published_at.isoformat()
            if chunk.freshness.published_at is not None
            else None,
            "staleness_class": chunk.freshness.staleness_class.value,
        },
        "metadata": dict(chunk.metadata),
        "document_index": chunk.document_index,
        "chunk_index": chunk.chunk_index,
    }


def _opensearch_document_id(tenant_id: str, evidence_id: str) -> str:
    _validate_tenant_id(tenant_id)
    if not evidence_id.strip():
        raise RagIndexConfigurationError("evidence_id must be non-empty")
    digest = hashlib.sha256(f"{tenant_id}\0{evidence_id}".encode("utf-8")).hexdigest()
    return f"tenant_{digest}"


def _evidence_from_opensearch_response(
    response: Mapping[str, object],
    search_request: RagSearchRequest,
) -> list[Evidence]:
    hits_section = response.get("hits")
    if not isinstance(hits_section, Mapping):
        return []
    raw_hits = hits_section.get("hits", [])
    if not isinstance(raw_hits, Sequence):
        return []
    evidence: list[Evidence] = []
    for raw_hit in raw_hits:
        if not isinstance(raw_hit, Mapping):
            continue
        source = raw_hit.get("_source")
        if not isinstance(source, Mapping):
            continue
        if source.get("tenant_id") != search_request.tenant_id:
            continue
        evidence.append(
            _evidence_from_source(
                source,
                search_request,
                ranker="opensearch_bm25_v1",
                score=raw_hit.get("_score"),
            )
        )
    return evidence


def _evidence_from_pgvector_row(
    row: Mapping[str, object],
    search_request: RagSearchRequest,
) -> Evidence:
    if row.get("tenant_id") != search_request.tenant_id:
        raise RagIndexTransportError("pgvector row tenant_id did not match search request")
    return _evidence_from_source(
        row,
        search_request,
        ranker="pgvector_v1",
        score=None,
    )


def _evidence_from_source(
    source: Mapping[str, object],
    search_request: RagSearchRequest,
    *,
    ranker: str,
    score: object,
) -> Evidence:
    metadata = _object_mapping(source.get("metadata"))
    freshness = _freshness_from_source(source)
    evidence_id = _required_string(source.get("evidence_id"), "evidence_id")
    structured_content: dict[str, object] = {
        "metadata": metadata,
        "retrieval": {
            "claim_id": search_request.claim_id,
            "ranker": ranker,
            "score": score,
            "tenant_scoped": True,
        },
    }
    structure = _structure_from_metadata(metadata)
    if structure:
        structured_content["structure"] = structure
    return Evidence(
        evidence_id=evidence_id,
        kind=EvidenceKind.DOCUMENT_CHUNK,
        source_ref=_required_string(source.get("source_ref"), "source_ref"),
        content=_required_string(source.get("content"), "content"),
        authority=_authority_from_value(source.get("authority")),
        freshness=freshness,
        structured_content=structured_content,
    )


def _pgvector_chunk_parameters(chunk: RagChunk, embedder: TextEmbedder) -> list[object]:
    _validate_tenant_id(chunk.tenant_id)
    return [
        chunk.tenant_id,
        chunk.evidence_id,
        chunk.source_ref,
        chunk.content,
        chunk.authority.value,
        chunk.freshness.staleness_class.value,
        chunk.freshness.published_at,
        json.dumps(dict(chunk.metadata), sort_keys=True),
        _pgvector_literal(embedder.embed(chunk.content)),
    ]


def _pgvector_literal(values: Sequence[float]) -> str:
    return "[" + ",".join(f"{value:.6f}" for value in values) + "]"


def _encode_opensearch_body(body: Mapping[str, object] | Sequence[object] | str) -> bytes:
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, Sequence) and not isinstance(body, (str, bytes, bytearray)):
        return ("\n".join(json.dumps(item, separators=(",", ":")) for item in body) + "\n").encode(
            "utf-8"
        )
    return json.dumps(body).encode("utf-8")


def _validate_search_request(search_request: RagSearchRequest) -> None:
    _validate_tenant_id(search_request.tenant_id)
    if not search_request.claim_id.strip():
        raise RagIndexConfigurationError("claim_id must be non-empty")
    if not search_request.query_text.strip():
        raise RagIndexConfigurationError("query_text must be non-empty")
    if search_request.max_results <= 0:
        raise RagIndexConfigurationError("max_results must be positive")


def _ensure_single_tenant(chunks: Sequence[RagChunk]) -> None:
    tenant_ids = {chunk.tenant_id for chunk in chunks}
    if len(tenant_ids) != 1:
        raise RagIndexConfigurationError("RAG index writes must contain exactly one tenant")


def _validate_tenant_id(tenant_id: str) -> None:
    if not tenant_id.strip():
        raise RagIndexConfigurationError("tenant_id must be non-empty")


def _validate_identifier(value: str, label: str) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise RagIndexConfigurationError(f"{label} must be a safe SQL/OpenSearch identifier")


def _validate_opensearch_template_payload(template: Mapping[str, object]) -> None:
    index_patterns = template.get("index_patterns")
    if not isinstance(index_patterns, Sequence) or isinstance(index_patterns, (str, bytes)):
        raise RagIndexConfigurationError("OpenSearch template index_patterns must be a list")
    if not all(isinstance(item, str) and item.strip() for item in index_patterns):
        raise RagIndexConfigurationError("OpenSearch template index_patterns must contain strings")
    template_body = template.get("template")
    if not isinstance(template_body, Mapping):
        raise RagIndexConfigurationError("OpenSearch template body must be an object")
    mappings = template_body.get("mappings")
    if not isinstance(mappings, Mapping):
        raise RagIndexConfigurationError("OpenSearch template mappings must be an object")


def _object_mapping(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _structure_from_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    heading = metadata.get(f"{STRUCTURAL_METADATA_PREFIX}section_heading")
    path = metadata.get(f"{STRUCTURAL_METADATA_PREFIX}section_path")
    level = metadata.get(f"{STRUCTURAL_METADATA_PREFIX}section_level")
    kind = metadata.get(f"{STRUCTURAL_METADATA_PREFIX}chunk_kind")
    if not isinstance(heading, str) or not heading.strip():
        return {}
    if not isinstance(path, str) or not path.strip():
        return {}
    if not isinstance(level, int) or isinstance(level, bool):
        return {}
    if not isinstance(kind, str) or not kind.strip():
        return {}
    return {
        "section_heading": heading,
        "section_path": [part.strip() for part in path.split(">") if part.strip()],
        "section_level": level,
        "chunk_kind": kind,
    }


def _freshness_from_source(source: Mapping[str, object]) -> Freshness:
    freshness = source.get("freshness")
    if isinstance(freshness, Mapping):
        retrieved_at = _parse_datetime(freshness.get("retrieved_at"))
        published_at = _parse_datetime(freshness.get("published_at"))
        staleness = _staleness_from_value(freshness.get("staleness_class"))
        return Freshness(
            retrieved_at=retrieved_at or Freshness().retrieved_at,
            published_at=published_at,
            staleness_class=staleness,
        )
    return Freshness(
        published_at=_parse_datetime(source.get("published_at")),
        staleness_class=_staleness_from_value(source.get("staleness_class")),
    )


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _authority_from_value(value: object) -> Authority:
    if isinstance(value, str):
        try:
            return Authority(value)
        except ValueError:
            return Authority.UNKNOWN
    return Authority.UNKNOWN


def _staleness_from_value(value: object) -> StalenessClass:
    if isinstance(value, str):
        try:
            return StalenessClass(value)
        except ValueError:
            return StalenessClass.UNKNOWN
    return StalenessClass.UNKNOWN


def _required_string(value: object, field_name: str) -> str:
    if isinstance(value, str) and value.strip():
        return value
    raise RagIndexTransportError(f"RAG index result missing non-empty {field_name}")
