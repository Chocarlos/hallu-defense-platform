from __future__ import annotations

import hashlib
import json
import math
import re
import ssl
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from importlib import import_module
from types import TracebackType
from typing import Iterator, Protocol, Self, cast
from urllib import error, request

from hallu_defense.config import (
    PRODUCTION_LIKE_ENVIRONMENTS,
    Settings,
    is_kind_internal_opensearch_http,
)
from hallu_defense.domain.models import (
    Authority,
    Evidence,
    EvidenceKind,
    Freshness,
    StalenessClass,
)
from hallu_defense.domain.rag_metadata import (
    RagMetadataValidationError,
    canonical_json,
    metadata_filter_token,
    metadata_filter_tokens,
    validate_metadata,
    validate_metadata_filter,
    validate_persistable_text,
)
from hallu_defense.outbound_http import (
    OutboundHttpPolicy,
    OutboundHttpPolicyError,
    OutboundHttpRedirectError,
    open_url_no_redirect,
    outbound_http_policy_from_settings,
)
from hallu_defense.services.secrets import (
    SecretAccessError,
    SecretConfigurationError,
    SecretManager,
    SecretNotFoundError,
    SecretValue,
    create_secret_manager,
)

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRUCTURAL_METADATA_PREFIX = "structural_"
CORPUS_ID_METADATA_KEY = "corpus_id"
DOCUMENT_REVISION_METADATA_KEY = "document_revision"
PGVECTOR_EMBEDDING_DIMENSION = 16
MAX_OPENSEARCH_HTTP_RESPONSE_BYTES = 1024 * 1024
MAX_OPENSEARCH_HTTP_REQUEST_BYTES = 8 * 1024 * 1024
MAX_EXACT_LOOKUP_IDS = 1000
HYBRID_RRF_K = 60
HYBRID_REVISION_LOCK_NAMESPACE = "hybrid_revision_v1:"
HYBRID_OPENSEARCH_RANKER = "opensearch_bm25_v1"
HYBRID_PGVECTOR_RANKER = "pgvector_cosine_v1"
HYBRID_RANKER = "persistent_hybrid_rrf_v1"
OPENSEARCH_TEMPLATE_SCHEMA_VERSION = "rag-opensearch-template.v3"
LEXICAL_TOKEN_PATTERN = re.compile(r"[^\W_]+", re.UNICODE)


class RagIndexError(RuntimeError):
    pass


class RagIndexConfigurationError(RagIndexError):
    pass


class RagIndexTransportError(RagIndexError):
    pass


class RagIndexTenantDeletedError(RagIndexError):
    """Raised before any persistent write for a durably deleted tenant."""


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
class RevisionReconciliationGroup:
    tenant_id: str
    source_ref: str
    corpus_id: str
    document_revision: str
    evidence_ids: tuple[str, ...]

    @property
    def lock_key(self) -> str:
        return json.dumps(
            [self.tenant_id, self.source_ref, self.corpus_id],
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class OpenSearchTemplateInstallResult:
    template_name: str
    path: str
    acknowledged: bool
    response: Mapping[str, object]


@dataclass(frozen=True)
class OpenSearchSchemaProvisionResult:
    template: OpenSearchTemplateInstallResult
    index_state: str


class RagIndexBackend(Protocol):
    backend_name: str

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        ...

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        ...


StorageIdentity = tuple[str, str]
StorageIdentities = frozenset[StorageIdentity]


class ExactLookupRagIndexBackend(RagIndexBackend, Protocol):
    def fetch_by_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> list[Evidence]:
        ...


class PersistentRagDeletionBackend(Protocol):
    def delete_tenant(self, *, tenant_id: str) -> int:
        """Delete every document for one tenant and verify that none remain."""

        ...

    def delete_evidence_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> int:
        """Delete one bounded tenant-scoped batch and verify that it is absent."""

        ...


class RevisionLockCoordinator(Protocol):
    def hold(self, lock_keys: Sequence[str]) -> AbstractContextManager[None]:
        ...


class TenantWriteFence(Protocol):
    def assert_writable(self, tenant_ids: Sequence[str]) -> None:
        ...


class RagIndexHealthProbe(Protocol):
    def health_check(self) -> None:
        ...


class TextEmbedder(Protocol):
    dimension: int

    def embed(self, text: str) -> list[float]:
        ...


class DeterministicHashEmbedder:
    """Small local lexical-vector baseline using signed feature hashing."""

    def __init__(self, dimension: int = 16) -> None:
        if dimension <= 0:
            raise RagIndexConfigurationError("embedding dimension must be positive")
        self.dimension = dimension

    def embed(self, text: str) -> list[float]:
        normalized = unicodedata.normalize("NFKC", text).casefold()
        token_counts = Counter(LEXICAL_TOKEN_PATTERN.findall(normalized))
        values = [0.0] * self.dimension
        if not token_counts and normalized.strip():
            digest = hashlib.sha256(f"fallback:{normalized}".encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:8], "big") % self.dimension
            values[bucket] = 1.0 if digest[8] & 1 else -1.0
        for token, count in sorted(token_counts.items()):
            digest = hashlib.sha256(f"token:{token}".encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:8], "big") % self.dimension
            sign = 1.0 if digest[8] & 1 else -1.0
            values[bucket] += sign * (1.0 + math.log(count))
        norm = math.sqrt(math.fsum(value * value for value in values))
        if norm == 0:
            return values
        return [value / norm for value in values]


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
    # This backend reconciles an entire document revision per call, so feeding
    # a corpus in independent pages would delete sibling-page evidence.
    backfill_page_safe = False

    def __init__(
        self,
        *,
        endpoint: str,
        index_name: str,
        timeout_seconds: float,
        transport: OpenSearchTransport | None = None,
        outbound_policy: OutboundHttpPolicy | None = None,
        authorization: SecretValue | None = None,
        ssl_context: ssl.SSLContext | None = None,
        require_green_health: bool = False,
        minimum_data_nodes: int = 1,
    ) -> None:
        if not endpoint.strip():
            raise RagIndexConfigurationError("OpenSearch endpoint must be configured")
        _validate_identifier(index_name, "OpenSearch index name")
        self._endpoint = endpoint.rstrip("/")
        effective_policy = outbound_policy or OutboundHttpPolicy.local_unrestricted()
        try:
            effective_policy.validate_url(self._endpoint)
        except OutboundHttpPolicyError:
            raise RagIndexConfigurationError(
                "OpenSearch endpoint is blocked by outbound policy."
            ) from None
        self._index_name = index_name
        self._timeout_seconds = timeout_seconds
        if minimum_data_nodes <= 0:
            raise RagIndexConfigurationError("OpenSearch minimum data nodes must be positive")
        self._require_green_health = require_green_health
        self._minimum_data_nodes = minimum_data_nodes
        if authorization is not None:
            _validate_opensearch_authorization(authorization)
        self._transport = transport or UrlLibOpenSearchTransport(
            self._endpoint,
            outbound_policy=effective_policy,
            authorization=authorization,
            ssl_context=ssl_context,
        )

    @property
    def storage_identities(self) -> StorageIdentities:
        return frozenset({(self.backend_name, self._index_name)})

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

    def provision_index_schema(
        self,
        *,
        template_name: str,
        template: Mapping[str, object],
    ) -> OpenSearchSchemaProvisionResult:
        """Install schema v3 and reject an existing index with stale mappings/settings."""

        _validate_opensearch_template_payload(template)
        _validate_opensearch_template_targets_index(
            template,
            index_name=self._index_name,
        )
        result = self.install_index_template(
            template_name=template_name,
            template=template,
        )
        if not result.acknowledged:
            raise RagIndexTransportError(
                "OpenSearch did not acknowledge index template provisioning."
            )
        installed = self._transport.request_json(
            "GET",
            f"/_index_template/{template_name}",
            {},
            timeout_seconds=self._timeout_seconds,
        )
        _validate_installed_opensearch_template(
            installed,
            template_name=template_name,
            index_name=self._index_name,
        )
        existing_mapping = self._transport.request_json(
            "GET",
            f"/{self._index_name}/_mapping?ignore_unavailable=true&expand_wildcards=all",
            {},
            timeout_seconds=self._timeout_seconds,
        )
        index_state = _validate_existing_opensearch_index_mapping(
            existing_mapping,
            index_name=self._index_name,
        )
        if index_state == "compatible":
            existing_settings = self._transport.request_json(
                "GET",
                f"/{self._index_name}/_settings?ignore_unavailable=true&expand_wildcards=all",
                {},
                timeout_seconds=self._timeout_seconds,
            )
            _validate_existing_opensearch_index_settings(
                existing_settings,
                index_name=self._index_name,
            )
        return OpenSearchSchemaProvisionResult(
            template=result,
            index_state=index_state,
        )

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        if not chunks:
            return RagIndexWriteResult(indexed_count=0, backend=self.backend_name)
        _ensure_single_tenant(chunks)
        ordered_chunks = sorted(chunks, key=lambda chunk: (chunk.source_ref, chunk.evidence_id))
        reconciliation_groups = _revision_reconciliation_groups(ordered_chunks)
        operations: list[object] = []
        for chunk in ordered_chunks:
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
        response = self._transport.request_json(
            "POST",
            "/_bulk?refresh=wait_for",
            operations,
            headers={"content-type": "application/x-ndjson"},
            timeout_seconds=self._timeout_seconds,
        )
        _raise_for_opensearch_bulk_errors(response)
        for group in reconciliation_groups:
            reconciliation_response = self._transport.request_json(
                "POST",
                f"/{self._index_name}/_delete_by_query?conflicts=proceed&refresh=true",
                _opensearch_reconciliation_query(group),
                timeout_seconds=self._timeout_seconds,
            )
            _raise_for_opensearch_reconciliation_errors(reconciliation_response)
        return RagIndexWriteResult(
            indexed_count=len(ordered_chunks),
            backend=self.backend_name,
            evidence_ids=[chunk.evidence_id for chunk in ordered_chunks],
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        _validate_search_request(search_request)
        filters: list[object] = [{"term": {"tenant_id": search_request.tenant_id}}]
        if search_request.context_refs:
            filters.append({"terms": {"source_ref": list(search_request.context_refs)}})
        for key, value in sorted(search_request.metadata_filter.items()):
            filters.append(
                {
                    "term": {
                        "metadata_filter_tokens": metadata_filter_token(key, value)
                    }
                }
            )

        body: dict[str, object] = {
            "size": search_request.max_results,
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": search_request.query_text,
                                "fields": ["content^2", "source_ref"],
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
        return _evidence_from_opensearch_response(
            response,
            search_request,
            ranker=HYBRID_OPENSEARCH_RANKER,
        )

    def fetch_by_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> list[Evidence]:
        normalized_ids = _validated_exact_lookup_ids(tenant_id, evidence_ids)
        if not normalized_ids:
            return []
        body: dict[str, object] = {
            "size": len(normalized_ids),
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"tenant_id": tenant_id}},
                        {"terms": {"evidence_id": normalized_ids}},
                    ]
                }
            },
            "sort": [{"evidence_id": {"order": "asc"}}],
        }
        response = self._transport.request_json(
            "POST",
            f"/{self._index_name}/_search",
            body,
            timeout_seconds=self._timeout_seconds,
        )
        lookup_request = RagSearchRequest(
            tenant_id=tenant_id,
            claim_id="hybrid_exact_lookup",
            query_text="hybrid exact lookup",
            max_results=len(normalized_ids),
        )
        evidence = _evidence_from_opensearch_response(
            response,
            lookup_request,
            ranker="opensearch_exact_lookup_v1",
        )
        _validate_exact_lookup_response(evidence, normalized_ids, backend_name=self.backend_name)
        return evidence

    def delete_evidence_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> int:
        normalized_ids = _validated_exact_lookup_ids(tenant_id, evidence_ids)
        if not normalized_ids:
            return 0
        query: dict[str, object] = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"tenant_id": tenant_id}},
                        {"terms": {"evidence_id": normalized_ids}},
                    ]
                }
            }
        }
        response = self._transport.request_json(
            "POST",
            f"/{self._index_name}/_delete_by_query?conflicts=proceed&refresh=true",
            query,
            timeout_seconds=self._timeout_seconds,
        )
        _raise_for_opensearch_lifecycle_deletion_errors(response)
        verification = self._transport.request_json(
            "POST",
            f"/{self._index_name}/_count",
            query,
            timeout_seconds=self._timeout_seconds,
        )
        remaining = verification.get("count")
        if (
            not isinstance(remaining, int)
            or isinstance(remaining, bool)
            or remaining != 0
            or "error" in verification
        ):
            raise RagIndexTransportError(
                "OpenSearch lifecycle deletion parity verification failed."
            )
        deleted = response.get("deleted")
        if not isinstance(deleted, int) or isinstance(deleted, bool) or deleted < 0:
            raise RagIndexTransportError(
                "OpenSearch lifecycle deletion response was invalid."
            )
        return deleted

    def delete_tenant(self, *, tenant_id: str) -> int:
        _validate_tenant_id(tenant_id)
        query: dict[str, object] = {
            "query": {"term": {"tenant_id": tenant_id}},
        }
        response = self._transport.request_json(
            "POST",
            f"/{self._index_name}/_delete_by_query?conflicts=proceed&refresh=true",
            query,
            timeout_seconds=self._timeout_seconds,
        )
        _raise_for_opensearch_lifecycle_deletion_errors(response)
        verification = self._transport.request_json(
            "POST",
            f"/{self._index_name}/_count",
            query,
            timeout_seconds=self._timeout_seconds,
        )
        remaining = verification.get("count")
        if (
            not isinstance(remaining, int)
            or isinstance(remaining, bool)
            or remaining != 0
            or "error" in verification
        ):
            raise RagIndexTransportError(
                "OpenSearch tenant deletion parity verification failed."
            )
        deleted = response.get("deleted")
        if not isinstance(deleted, int) or isinstance(deleted, bool) or deleted < 0:
            raise RagIndexTransportError(
                "OpenSearch tenant deletion response was invalid."
            )
        return deleted

    def health_check(self) -> None:
        response = self._transport.request_json(
            "GET",
            "/_cluster/health",
            {},
            timeout_seconds=self._timeout_seconds,
        )
        _validate_opensearch_health_response(
            response,
            require_green=self._require_green_health,
            minimum_data_nodes=self._minimum_data_nodes,
        )


class PgVectorConnection(Protocol):
    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        ...

    def execute_many_transactionally(
        self,
        operations: Sequence[tuple[str, Sequence[Sequence[object]]]],
    ) -> None:
        ...

    def fetch_all(self, statement: str, parameters: Sequence[object]) -> Sequence[Mapping[str, object]]:
        ...


class PgVectorPsycopgCursor(Protocol):
    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        ...

    def execute(self, statement: str, parameters: Sequence[object]) -> None:
        ...

    def executemany(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        ...

    def fetchall(self) -> Sequence[Mapping[str, object]]:
        ...


class PgVectorPsycopgConnection(Protocol):
    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        ...

    def cursor(self) -> PgVectorPsycopgCursor:
        ...


class PgVectorPsycopgConnect(Protocol):
    def __call__(
        self,
        conninfo: str,
        *,
        row_factory: object | None = None,
    ) -> PgVectorPsycopgConnection:
        ...


class PsycopgPgVectorConnection:
    def __init__(
        self,
        *,
        dsn: str,
        connect: PgVectorPsycopgConnect | None = None,
        row_factory: object | None = None,
    ) -> None:
        if not dsn.strip():
            raise RagIndexConfigurationError("Postgres DSN must be configured.")
        if connect is None:
            connect, row_factory = _load_psycopg_connect()
        self._dsn = dsn
        self._connect = connect
        self._row_factory = row_factory

    def execute_many(self, statement: str, parameters: Sequence[Sequence[object]]) -> None:
        try:
            with self._connect(self._dsn, row_factory=self._row_factory) as connection:
                with connection.cursor() as cursor:
                    cursor.executemany(statement, parameters)
        except Exception:
            raise RagIndexTransportError("pgvector execute_many failed") from None

    def execute_many_transactionally(
        self,
        operations: Sequence[tuple[str, Sequence[Sequence[object]]]],
    ) -> None:
        try:
            with self._connect(self._dsn, row_factory=self._row_factory) as connection:
                with connection.cursor() as cursor:
                    for statement, parameters in operations:
                        cursor.executemany(statement, parameters)
        except Exception:
            raise RagIndexTransportError("pgvector transactional write failed") from None

    def fetch_all(self, statement: str, parameters: Sequence[object]) -> Sequence[Mapping[str, object]]:
        try:
            with self._connect(self._dsn, row_factory=self._row_factory) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(statement, parameters)
                    return cursor.fetchall()
        except Exception:
            raise RagIndexTransportError("pgvector fetch_all failed") from None


class PostgresTenantDeletionFence:
    """Database-authoritative tenant tombstone check used inside the write lock."""

    def __init__(self, connection: PgVectorConnection) -> None:
        self._connection = connection

    def assert_writable(self, tenant_ids: Sequence[str]) -> None:
        normalized = tuple(sorted(set(tenant_ids)))
        for tenant_id in normalized:
            _validate_tenant_id(tenant_id)
        if not normalized:
            return
        rows = self._connection.fetch_all(
            "SELECT tenant_id FROM rag_tenant_deletion_tombstones "
            "WHERE tenant_id = ANY(%s) ORDER BY tenant_id ASC LIMIT 1",
            (list(normalized),),
        )
        if not rows:
            return
        blocked_tenant = rows[0].get("tenant_id")
        if blocked_tenant not in normalized:
            raise RagIndexTransportError(
                "Tenant deletion fence returned an inconsistent tenant boundary."
            )
        raise RagIndexTenantDeletedError(
            "Persistent RAG write is blocked for a durably deleted tenant."
        )


class PgVectorRagIndexBackend:
    backend_name = "pgvector"
    backfill_page_safe = False

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

    @property
    def storage_identity(self) -> tuple[str, str]:
        return (self.backend_name, self._table_name)

    @property
    def storage_identities(self) -> StorageIdentities:
        return frozenset({self.storage_identity})

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        if not chunks:
            return RagIndexWriteResult(indexed_count=0, backend=self.backend_name)
        _ensure_single_tenant(chunks)
        statement = (
            f"INSERT INTO {self._table_name} "
            "(tenant_id, evidence_id, source_ref, content, authority, staleness_class, "
            "retrieved_at, published_at, metadata, embedding) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::vector) "
            "ON CONFLICT (tenant_id, evidence_id) DO UPDATE SET "
            "source_ref = EXCLUDED.source_ref, content = EXCLUDED.content, "
            "authority = EXCLUDED.authority, staleness_class = EXCLUDED.staleness_class, "
            "retrieved_at = EXCLUDED.retrieved_at, published_at = EXCLUDED.published_at, "
            "metadata = EXCLUDED.metadata, "
            "embedding = EXCLUDED.embedding, updated_at = now()"
        )
        ordered_chunks = sorted(chunks, key=lambda chunk: (chunk.source_ref, chunk.evidence_id))
        parameters = [
            _pgvector_chunk_parameters(chunk, self._embedder) for chunk in ordered_chunks
        ]
        reconciliation_groups = _revision_reconciliation_groups(ordered_chunks)
        reconciliation_parameters = _pgvector_reconciliation_parameters(
            reconciliation_groups
        )
        if reconciliation_parameters:
            lock_statement = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))"
            legacy_lock_parameters = [
                [
                    json.dumps(
                        [group.tenant_id, group.source_ref, parameters[2]],
                        separators=(",", ":"),
                    )
                ]
                for group, parameters in zip(
                    reconciliation_groups, reconciliation_parameters, strict=True
                )
            ]
            authoritative_lock_parameters = [
                [
                    json.dumps(
                        [group.tenant_id, group.source_ref, group.corpus_id],
                        separators=(",", ":"),
                    )
                ]
                for group in reconciliation_groups
            ]
            # Keep the historical JSON-filter lock first for rolling-upgrade
            # exclusion with older API/worker pods, then acquire the stable
            # authoritative corpus lock used by this version.
            lock_parameters = (
                legacy_lock_parameters + authoritative_lock_parameters
            )
            reconciliation_statement = (
                f"DELETE FROM {self._table_name} "
                "WHERE tenant_id = %s AND source_ref = %s "
                "AND metadata @> %s::jsonb "
                "AND (metadata ->> 'document_revision' IS DISTINCT FROM %s "
                "OR evidence_id <> ALL(%s))"
            )
            self._connection.execute_many_transactionally(
                (
                    (lock_statement, lock_parameters),
                    (statement, parameters),
                    (reconciliation_statement, reconciliation_parameters),
                )
            )
        else:
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
        for key, value in sorted(search_request.metadata_filter.items()):
            filters.append("(metadata @> %s::jsonb AND metadata -> %s = %s::jsonb)")
            filter_parameters.extend(
                [canonical_json({key: value}), key, canonical_json(value)]
            )
        parameters = [
            _pgvector_literal(embedding),
            *filter_parameters,
            search_request.max_results,
        ]
        statement = (
            "SELECT tenant_id, evidence_id, source_ref, content, authority, staleness_class, "
            f"retrieved_at, published_at, metadata, "
            f"1 - (embedding <=> %s::vector) AS vector_score "
            f"FROM {self._table_name} "
            f"WHERE {' AND '.join(filters)} "
            "ORDER BY vector_score DESC, evidence_id ASC "
            "LIMIT %s"
        )
        rows = self._connection.fetch_all(statement, parameters)
        return [
            _evidence_from_pgvector_row(
                row,
                search_request,
                ranker=HYBRID_PGVECTOR_RANKER,
                score=row.get("vector_score"),
            )
            for row in rows
        ]

    def fetch_by_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> list[Evidence]:
        normalized_ids = _validated_exact_lookup_ids(tenant_id, evidence_ids)
        if not normalized_ids:
            return []
        statement = (
            "SELECT tenant_id, evidence_id, source_ref, content, authority, staleness_class, "
            f"retrieved_at, published_at, metadata FROM {self._table_name} "
            "WHERE tenant_id = %s AND evidence_id = ANY(%s) "
            "ORDER BY evidence_id ASC"
        )
        rows = self._connection.fetch_all(statement, (tenant_id, normalized_ids))
        lookup_request = RagSearchRequest(
            tenant_id=tenant_id,
            claim_id="hybrid_exact_lookup",
            query_text="hybrid exact lookup",
            max_results=len(normalized_ids),
        )
        evidence = [
            _evidence_from_pgvector_row(
                row,
                lookup_request,
                ranker="pgvector_exact_lookup_v1",
                score=None,
            )
            for row in rows
        ]
        _validate_exact_lookup_response(evidence, normalized_ids, backend_name=self.backend_name)
        return evidence


class HybridRevisionLockCursor(Protocol):
    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...

    def execute(self, statement: str, parameters: Sequence[object]) -> None: ...

    def fetchone(self) -> Mapping[str, object] | Sequence[object] | None: ...


class HybridRevisionLockConnection(Protocol):
    def cursor(self) -> HybridRevisionLockCursor: ...

    def close(self) -> None: ...


class HybridRevisionLockConnect(Protocol):
    def __call__(
        self,
        conninfo: str,
        *,
        autocommit: bool,
        connect_timeout: int,
        options: str,
        row_factory: object | None = None,
    ) -> HybridRevisionLockConnection: ...


class PostgresHybridRevisionLockCoordinator:
    """Serialize dual-store revisions without replacing pgvector's xact lock."""

    def __init__(
        self,
        *,
        dsn: str,
        connect: HybridRevisionLockConnect,
        timeout_seconds: float,
        row_factory: object | None = None,
    ) -> None:
        if not dsn.strip():
            raise RagIndexConfigurationError("Hybrid revision locking requires PostgreSQL.")
        if timeout_seconds <= 0 or not math.isfinite(timeout_seconds):
            raise RagIndexConfigurationError(
                "Hybrid revision lock timeout must be positive and finite."
            )
        self._dsn = dsn
        self._connect = connect
        self._timeout_seconds = timeout_seconds
        self._row_factory = row_factory

    @contextmanager
    def hold(self, lock_keys: Sequence[str]) -> Iterator[None]:
        ordered_keys = sorted(set(lock_keys))
        if not ordered_keys:
            yield
            return
        connection: HybridRevisionLockConnection | None = None
        timeout_milliseconds = max(1, math.ceil(self._timeout_seconds * 1000))
        try:
            connection = self._connect(
                self._dsn,
                autocommit=True,
                connect_timeout=max(1, math.ceil(self._timeout_seconds)),
                options=(
                    f"-c lock_timeout={timeout_milliseconds} "
                    f"-c statement_timeout={timeout_milliseconds}"
                ),
                row_factory=self._row_factory,
            )
            with connection.cursor() as cursor:
                for lock_key in ordered_keys:
                    cursor.execute(
                        "SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                        (HYBRID_REVISION_LOCK_NAMESPACE + lock_key,),
                    )
        except Exception:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            raise RagIndexTransportError(
                "Hybrid revision lock acquisition failed."
            ) from None

        body_succeeded = False
        try:
            yield
            body_succeeded = True
        finally:
            release_error = False
            try:
                with connection.cursor() as cursor:
                    for lock_key in reversed(ordered_keys):
                        cursor.execute(
                            "SELECT pg_advisory_unlock(hashtextextended(%s, 0)) AS unlocked",
                            (HYBRID_REVISION_LOCK_NAMESPACE + lock_key,),
                        )
                        if not _advisory_unlock_succeeded(cursor.fetchone()):
                            release_error = True
            except Exception:
                release_error = True
            try:
                connection.close()
            except Exception:
                release_error = True
            if release_error and body_succeeded:
                raise RagIndexTransportError("Hybrid revision lock release failed.")


@dataclass(frozen=True)
class _RankObservation:
    evidence: Evidence
    rank: int
    score: float


class HybridRagIndexBackend:
    backend_name = "hybrid"
    backfill_page_safe = False

    def __init__(
        self,
        *,
        opensearch: ExactLookupRagIndexBackend,
        pgvector: ExactLookupRagIndexBackend,
        revision_locks: RevisionLockCoordinator,
        tenant_write_fence: TenantWriteFence,
    ) -> None:
        if opensearch.backend_name != "opensearch":
            raise RagIndexConfigurationError("Hybrid RAG requires an OpenSearch backend.")
        if pgvector.backend_name != "pgvector":
            raise RagIndexConfigurationError("Hybrid RAG requires a pgvector backend.")
        self._opensearch = opensearch
        self._pgvector = pgvector
        self._revision_locks = revision_locks
        self._tenant_write_fence = tenant_write_fence

    @property
    def storage_identities(self) -> StorageIdentities:
        opensearch_identities = getattr(self._opensearch, "storage_identities", None)
        pgvector_identities = getattr(self._pgvector, "storage_identities", None)
        if not isinstance(opensearch_identities, frozenset) or not isinstance(
            pgvector_identities,
            frozenset,
        ):
            return frozenset()
        return opensearch_identities | pgvector_identities

    def index_chunks(self, chunks: Sequence[RagChunk]) -> RagIndexWriteResult:
        if not chunks:
            return RagIndexWriteResult(indexed_count=0, backend=self.backend_name)
        _ensure_single_tenant(chunks)
        ordered_chunks = sorted(chunks, key=lambda chunk: (chunk.source_ref, chunk.evidence_id))
        expected_ids = [chunk.evidence_id for chunk in ordered_chunks]
        lock_keys = _hybrid_write_lock_keys(ordered_chunks)
        with self._revision_locks.hold(lock_keys):
            self._tenant_write_fence.assert_writable(
                [chunk.tenant_id for chunk in ordered_chunks]
            )
            opensearch_result = self._opensearch.index_chunks(ordered_chunks)
            _validate_hybrid_write_result(
                opensearch_result,
                expected_ids=expected_ids,
                expected_backend="opensearch",
            )
            pgvector_result = self._pgvector.index_chunks(ordered_chunks)
            _validate_hybrid_write_result(
                pgvector_result,
                expected_ids=expected_ids,
                expected_backend="pgvector",
            )
        return RagIndexWriteResult(
            indexed_count=len(ordered_chunks),
            backend=self.backend_name,
            evidence_ids=expected_ids,
        )

    def search(self, search_request: RagSearchRequest) -> list[Evidence]:
        _validate_search_request(search_request)
        opensearch_ranked = self._ranked_results(
            self._opensearch.search(search_request),
            tenant_id=search_request.tenant_id,
            expected_ranker=HYBRID_OPENSEARCH_RANKER,
        )
        pgvector_ranked = self._ranked_results(
            self._pgvector.search(search_request),
            tenant_id=search_request.tenant_id,
            expected_ranker=HYBRID_PGVECTOR_RANKER,
        )
        union_ids = sorted(set(opensearch_ranked) | set(pgvector_ranked))
        if not union_ids:
            return []

        opensearch_exact = self._exact_results(
            self._opensearch.fetch_by_ids(
                tenant_id=search_request.tenant_id,
                evidence_ids=union_ids,
            ),
            tenant_id=search_request.tenant_id,
        )
        pgvector_exact = self._exact_results(
            self._pgvector.fetch_by_ids(
                tenant_id=search_request.tenant_id,
                evidence_ids=union_ids,
            ),
            tenant_id=search_request.tenant_id,
        )
        if set(opensearch_exact) != set(union_ids) or set(pgvector_exact) != set(union_ids):
            raise RagIndexTransportError(
                "Hybrid exact lookup found a partial persistent write."
            )

        fused: list[tuple[float, float, str, Evidence]] = []
        for evidence_id in union_ids:
            canonical = opensearch_exact[evidence_id]
            _assert_canonical_evidence_match(
                canonical,
                pgvector_exact[evidence_id],
                tenant_id=search_request.tenant_id,
            )
            if evidence_id in opensearch_ranked:
                _assert_canonical_evidence_match(
                    opensearch_ranked[evidence_id].evidence,
                    canonical,
                    tenant_id=search_request.tenant_id,
                )
            if evidence_id in pgvector_ranked:
                _assert_canonical_evidence_match(
                    pgvector_ranked[evidence_id].evidence,
                    pgvector_exact[evidence_id],
                    tenant_id=search_request.tenant_id,
                )
            traced, total_score, rrf_score = _with_hybrid_retrieval_trace(
                canonical,
                claim_id=search_request.claim_id,
                tenant_id=search_request.tenant_id,
                opensearch=opensearch_ranked.get(evidence_id),
                pgvector=pgvector_ranked.get(evidence_id),
            )
            fused.append((total_score, rrf_score, evidence_id, traced))

        fused.sort(key=lambda item: (-item[0], -item[1], item[2]))
        ranked: list[Evidence] = []
        for fused_rank, (_total, _rrf, _evidence_id, evidence) in enumerate(fused, start=1):
            retrieval = _retrieval_mapping(evidence)
            ranked.append(
                evidence.model_copy(
                    update={
                        "structured_content": {
                            **evidence.structured_content,
                            "retrieval": {**retrieval, "fused_rank": fused_rank},
                        }
                    }
                )
            )
        return ranked[: search_request.max_results]

    def fetch_by_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> list[Evidence]:
        normalized_ids = _validated_exact_lookup_ids(tenant_id, evidence_ids)
        opensearch = self._exact_results(
            self._opensearch.fetch_by_ids(
                tenant_id=tenant_id,
                evidence_ids=normalized_ids,
            ),
            tenant_id=tenant_id,
        )
        pgvector = self._exact_results(
            self._pgvector.fetch_by_ids(
                tenant_id=tenant_id,
                evidence_ids=normalized_ids,
            ),
            tenant_id=tenant_id,
        )
        if set(opensearch) != set(normalized_ids) or set(pgvector) != set(normalized_ids):
            raise RagIndexTransportError("Hybrid exact lookup found a partial persistent write.")
        evidence: list[Evidence] = []
        for evidence_id in normalized_ids:
            _assert_canonical_evidence_match(
                opensearch[evidence_id],
                pgvector[evidence_id],
                tenant_id=tenant_id,
            )
            evidence.append(opensearch[evidence_id])
        return evidence

    def delete_evidence_ids(
        self,
        *,
        tenant_id: str,
        evidence_ids: Sequence[str],
    ) -> int:
        deleter = cast(PersistentRagDeletionBackend, self._opensearch)
        return deleter.delete_evidence_ids(
            tenant_id=tenant_id,
            evidence_ids=evidence_ids,
        )

    def delete_tenant(self, *, tenant_id: str) -> int:
        deleter = cast(PersistentRagDeletionBackend, self._opensearch)
        return deleter.delete_tenant(tenant_id=tenant_id)

    def health_check(self) -> None:
        probe = cast(RagIndexHealthProbe, self._opensearch)
        probe.health_check()

    def _ranked_results(
        self,
        results: Sequence[Evidence],
        *,
        tenant_id: str,
        expected_ranker: str,
    ) -> dict[str, _RankObservation]:
        ranked: dict[str, _RankObservation] = {}
        for rank, evidence in enumerate(results, start=1):
            _validate_evidence_tenant_trace(evidence, tenant_id)
            retrieval = _retrieval_mapping(evidence)
            if retrieval.get("ranker") != expected_ranker:
                raise RagIndexTransportError("Hybrid backend returned an unexpected ranker trace.")
            score = _finite_score(retrieval.get("score"))
            if evidence.evidence_id in ranked:
                raise RagIndexTransportError("Hybrid backend returned a duplicate evidence_id.")
            ranked[evidence.evidence_id] = _RankObservation(evidence, rank, score)
        return ranked

    def _exact_results(
        self,
        results: Sequence[Evidence],
        *,
        tenant_id: str,
    ) -> dict[str, Evidence]:
        exact: dict[str, Evidence] = {}
        for evidence in results:
            _validate_evidence_tenant_trace(evidence, tenant_id)
            if evidence.evidence_id in exact:
                raise RagIndexTransportError("Exact lookup returned a duplicate evidence_id.")
            exact[evidence.evidence_id] = evidence
        return exact


class UrlLibOpenSearchTransport:
    def __init__(
        self,
        endpoint: str,
        *,
        outbound_policy: OutboundHttpPolicy | None = None,
        ssl_context: ssl.SSLContext | None = None,
        authorization: SecretValue | None = None,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._outbound_policy = outbound_policy or OutboundHttpPolicy.local_unrestricted()
        try:
            self._outbound_policy.validate_url(self._endpoint)
        except OutboundHttpPolicyError:
            raise RagIndexConfigurationError(
                "OpenSearch endpoint is blocked by outbound policy."
            ) from None
        self._ssl_context = ssl_context
        if authorization is not None:
            _validate_opensearch_authorization(authorization)
        self._authorization = authorization

    def request_json(
        self,
        method: str,
        path: str,
        body: Mapping[str, object] | Sequence[object] | str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        url = f"{self._endpoint}{path}"
        try:
            self._outbound_policy.validate_url(url)
        except OutboundHttpPolicyError:
            raise RagIndexTransportError(
                "OpenSearch endpoint is blocked by outbound policy."
            ) from None
        encoded_body = _encode_opensearch_body(body)
        if len(encoded_body) > MAX_OPENSEARCH_HTTP_REQUEST_BYTES:
            raise RagIndexTransportError(
                "OpenSearch request exceeded the configured safety limit."
            )
        request_headers = dict(headers or {"content-type": "application/json"})
        has_caller_authorization = any(
            name.lower() == "authorization" for name in request_headers
        )
        if self._authorization is not None and has_caller_authorization:
            raise RagIndexTransportError(
                "OpenSearch callers cannot override the configured authorization header."
            )
        if self._authorization is not None:
            request_headers["Authorization"] = self._authorization.reveal()
        req = request.Request(
            url,
            data=encoded_body,
            method=method,
            headers=request_headers,
        )
        try:
            with open_url_no_redirect(
                req,
                timeout=timeout_seconds,
                context=self._ssl_context,
            ) as response:
                raw_payload = response.read(MAX_OPENSEARCH_HTTP_RESPONSE_BYTES + 1)
        except OutboundHttpRedirectError:
            raise RagIndexTransportError("OpenSearch redirects are not allowed.") from None
        except error.HTTPError as exc:
            status_code = exc.code
            try:
                exc.close()
            finally:
                raise RagIndexTransportError(
                    f"OpenSearch request failed with HTTP status {status_code}."
                ) from None
        except (error.URLError, TimeoutError, OSError):
            raise RagIndexTransportError("OpenSearch request failed.") from None
        if len(raw_payload) > MAX_OPENSEARCH_HTTP_RESPONSE_BYTES:
            raise RagIndexTransportError(
                "OpenSearch response exceeded the 1 MiB safety limit."
            )
        try:
            payload = raw_payload.decode("utf-8")
        except UnicodeDecodeError:
            raise RagIndexTransportError(
                "OpenSearch response was not valid UTF-8 JSON."
            ) from None
        if not payload.strip():
            return {}
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            raise RagIndexTransportError(
                "OpenSearch response was not valid JSON."
            ) from None
        if not isinstance(decoded, Mapping):
            raise RagIndexTransportError("OpenSearch response must be a JSON object")
        return decoded


def create_rag_index_backend(
    settings: Settings,
    secret_manager: SecretManager | None = None,
) -> RagIndexBackend | None:
    backend = settings.rag_index_backend.strip().lower()
    if backend == "local":
        return None
    if backend in {"opensearch", "hybrid"}:
        opensearch = create_opensearch_rag_backend(
            settings,
            secret_manager=secret_manager,
        )
        if backend == "opensearch":
            return opensearch
    if backend == "pgvector":
        return _create_pgvector_backend(settings)
    if backend == "hybrid":
        connect, row_factory = _load_psycopg_connect()
        pgvector = _create_pgvector_backend(
            settings,
            connect=connect,
            row_factory=row_factory,
        )
        dsn = _required_postgres_dsn(settings)
        revision_locks = PostgresHybridRevisionLockCoordinator(
            dsn=dsn,
            connect=cast(HybridRevisionLockConnect, connect),
            timeout_seconds=settings.rag_index_timeout_seconds,
            row_factory=row_factory,
        )
        tenant_write_fence = PostgresTenantDeletionFence(
            PsycopgPgVectorConnection(
                dsn=dsn,
                connect=connect,
                row_factory=row_factory,
            )
        )
        return HybridRagIndexBackend(
            opensearch=opensearch,
            pgvector=pgvector,
            revision_locks=revision_locks,
            tenant_write_fence=tenant_write_fence,
        )
    raise RagIndexConfigurationError(f"Unsupported RAG index backend: {settings.rag_index_backend}")


def create_opensearch_rag_backend(
    settings: Settings,
    *,
    secret_manager: SecretManager | None,
) -> OpenSearchRagIndexBackend:
    production_external = (
        settings.environment.strip().lower() in PRODUCTION_LIKE_ENVIRONMENTS
        and not is_kind_internal_opensearch_http(settings)
    )
    try:
        outbound_policy = (
            OutboundHttpPolicy.local_unrestricted()
            if is_kind_internal_opensearch_http(settings)
            else outbound_http_policy_from_settings(settings)
        )
    except OutboundHttpPolicyError:
        raise RagIndexConfigurationError("OpenSearch outbound policy is invalid.") from None
    authorization: SecretValue | None = None
    secret_name = settings.opensearch_authorization_secret_name
    if secret_name is not None:
        manager = secret_manager or create_secret_manager(settings)
        try:
            authorization = manager.get_secret(secret_name)
        except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
            raise RagIndexConfigurationError(
                "OpenSearch authorization could not be loaded from SecretManager."
            ) from None
    ssl_context: ssl.SSLContext | None = None
    if settings.opensearch_ca_cert_path is not None:
        try:
            ssl_context = ssl.create_default_context(
                cafile=str(settings.opensearch_ca_cert_path)
            )
        except (OSError, ssl.SSLError):
            raise RagIndexConfigurationError(
                "OpenSearch CA certificate could not be loaded."
            ) from None
    return OpenSearchRagIndexBackend(
        endpoint=settings.opensearch_endpoint,
        index_name=settings.opensearch_index_name,
        timeout_seconds=settings.rag_index_timeout_seconds,
        outbound_policy=outbound_policy,
        authorization=authorization,
        ssl_context=ssl_context,
        require_green_health=production_external,
        minimum_data_nodes=2 if production_external else 1,
    )


def _create_pgvector_backend(
    settings: Settings,
    *,
    connect: PgVectorPsycopgConnect | None = None,
    row_factory: object | None = None,
) -> PgVectorRagIndexBackend:
    _validate_identifier(settings.pgvector_table_name, "pgvector table name")
    dsn = _required_postgres_dsn(settings)
    if settings.rag_embedding_dimension != PGVECTOR_EMBEDDING_DIMENSION:
        raise RagIndexConfigurationError(
            "pgvector backend requires HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION=16 "
            "to match infra/rag/pgvector/001_rag_evidence_chunks.sql"
        )
    return PgVectorRagIndexBackend(
        table_name=settings.pgvector_table_name,
        connection=PsycopgPgVectorConnection(
            dsn=dsn,
            connect=connect,
            row_factory=row_factory,
        ),
        embedder=DeterministicHashEmbedder(dimension=PGVECTOR_EMBEDDING_DIMENSION),
    )


def _required_postgres_dsn(settings: Settings) -> str:
    dsn = settings.postgres_dsn
    if dsn is None or not dsn.strip():
        raise RagIndexConfigurationError(
            "pgvector backend requires HALLU_DEFENSE_POSTGRES_DSN."
        )
    return dsn


def _load_psycopg_connect() -> tuple[PgVectorPsycopgConnect, object]:
    try:
        psycopg_module = import_module("psycopg")
        rows_module = import_module("psycopg.rows")
    except ImportError as exc:
        raise RagIndexConfigurationError(
            "pgvector backend requires the psycopg package."
        ) from exc
    connect = getattr(psycopg_module, "connect")
    dict_row = getattr(rows_module, "dict_row")
    if not callable(connect):
        raise RagIndexConfigurationError("psycopg.connect is not callable.")
    return cast(PgVectorPsycopgConnect, connect), dict_row


def _opensearch_source_from_chunk(chunk: RagChunk) -> dict[str, object]:
    try:
        metadata = dict(validate_metadata(chunk.metadata))
    except RagMetadataValidationError as exc:
        raise RagIndexConfigurationError(str(exc)) from None
    source: dict[str, object] = {
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
        "metadata": metadata,
        "metadata_filter_tokens": metadata_filter_tokens(metadata),
        "document_index": chunk.document_index,
        "chunk_index": chunk.chunk_index,
    }
    corpus_id = metadata.get(CORPUS_ID_METADATA_KEY)
    if isinstance(corpus_id, str) and corpus_id.strip():
        source[CORPUS_ID_METADATA_KEY] = corpus_id
    document_revision = metadata.get(DOCUMENT_REVISION_METADATA_KEY)
    if isinstance(document_revision, str) and document_revision.strip():
        source[DOCUMENT_REVISION_METADATA_KEY] = document_revision
    return source


def _opensearch_document_id(tenant_id: str, evidence_id: str) -> str:
    _validate_tenant_id(tenant_id)
    if not evidence_id.strip():
        raise RagIndexConfigurationError("evidence_id must be non-empty")
    digest = hashlib.sha256(f"{tenant_id}\0{evidence_id}".encode("utf-8")).hexdigest()
    return f"tenant_{digest}"


def _raise_for_opensearch_bulk_errors(response: Mapping[str, object]) -> None:
    if response.get("errors") is not True:
        return
    failure_status: int | None = None
    items = response.get("items")
    if isinstance(items, Sequence) and not isinstance(items, (str, bytes, bytearray)):
        for item in items:
            if not isinstance(item, Mapping):
                continue
            operation = item.get("index")
            if not isinstance(operation, Mapping):
                continue
            status = operation.get("status")
            if (
                isinstance(status, int)
                and not isinstance(status, bool)
                and 400 <= status <= 599
            ):
                failure_status = status
                break
    if failure_status is not None:
        raise RagIndexTransportError(
            f"OpenSearch bulk indexing failed with HTTP status {failure_status}."
        )
    raise RagIndexTransportError("OpenSearch bulk indexing failed.")


def _evidence_from_opensearch_response(
    response: Mapping[str, object],
    search_request: RagSearchRequest,
    *,
    ranker: str,
) -> list[Evidence]:
    if "error" in response:
        raise RagIndexTransportError("OpenSearch search response reported an error.")
    hits_section = response.get("hits")
    if not isinstance(hits_section, Mapping):
        raise RagIndexTransportError("OpenSearch search response is missing hits.")
    raw_hits = hits_section.get("hits")
    if not isinstance(raw_hits, Sequence) or isinstance(raw_hits, (str, bytes, bytearray)):
        raise RagIndexTransportError("OpenSearch search response hits are invalid.")
    evidence: list[Evidence] = []
    for raw_hit in raw_hits:
        if not isinstance(raw_hit, Mapping):
            raise RagIndexTransportError("OpenSearch search hit is invalid.")
        source = raw_hit.get("_source")
        if not isinstance(source, Mapping):
            raise RagIndexTransportError("OpenSearch search hit is missing _source.")
        if source.get("tenant_id") != search_request.tenant_id:
            raise RagIndexTransportError(
                "OpenSearch result tenant_id did not match search request."
            )
        evidence.append(
            _evidence_from_source(
                source,
                search_request,
                ranker=ranker,
                score=raw_hit.get("_score"),
            )
        )
    return evidence


def _evidence_from_pgvector_row(
    row: Mapping[str, object],
    search_request: RagSearchRequest,
    *,
    ranker: str,
    score: object,
) -> Evidence:
    if row.get("tenant_id") != search_request.tenant_id:
        raise RagIndexTransportError("pgvector row tenant_id did not match search request")
    return _evidence_from_source(
        row,
        search_request,
        ranker=ranker,
        score=score,
    )


def _evidence_from_source(
    source: Mapping[str, object],
    search_request: RagSearchRequest,
    *,
    ranker: str,
    score: object,
) -> Evidence:
    raw_metadata = source.get("metadata")
    if not isinstance(raw_metadata, Mapping):
        raise RagIndexTransportError("Persistent RAG evidence metadata is invalid.")
    try:
        metadata = dict(validate_metadata(raw_metadata))
    except RagMetadataValidationError:
        raise RagIndexTransportError("Persistent RAG evidence metadata is invalid.") from None
    freshness = _freshness_from_source(source)
    evidence_id = _required_string(source.get("evidence_id"), "evidence_id")
    structured_content: dict[str, object] = {
        "metadata": metadata,
        "retrieval": {
            "claim_id": search_request.claim_id,
            "ranker": ranker,
            "score": score,
            "tenant_id": search_request.tenant_id,
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
    try:
        metadata = validate_metadata(chunk.metadata)
    except RagMetadataValidationError as exc:
        raise RagIndexConfigurationError(str(exc)) from None
    return [
        chunk.tenant_id,
        chunk.evidence_id,
        chunk.source_ref,
        chunk.content,
        chunk.authority.value,
        chunk.freshness.staleness_class.value,
        chunk.freshness.retrieved_at,
        chunk.freshness.published_at,
        canonical_json(metadata),
        _pgvector_literal(embedder.embed(chunk.content)),
    ]


def _pgvector_reconciliation_parameters(
    groups: Sequence[RevisionReconciliationGroup],
) -> list[list[object]]:
    return [
        [
            group.tenant_id,
            group.source_ref,
            json.dumps({CORPUS_ID_METADATA_KEY: group.corpus_id}, sort_keys=True),
            group.document_revision,
            list(group.evidence_ids),
        ]
        for group in groups
    ]


def _revision_reconciliation_groups(
    chunks: Sequence[RagChunk],
) -> list[RevisionReconciliationGroup]:
    revisions: dict[tuple[str, str, str], tuple[str, set[str]]] = {}
    for chunk in chunks:
        corpus_id = chunk.metadata.get(CORPUS_ID_METADATA_KEY)
        revision = chunk.metadata.get(DOCUMENT_REVISION_METADATA_KEY)
        if not isinstance(corpus_id, str) or not corpus_id.strip():
            continue
        if not isinstance(revision, str) or not revision.strip():
            continue
        key = (chunk.tenant_id, chunk.source_ref, corpus_id)
        existing = revisions.get(key)
        if existing is None:
            revisions[key] = (revision, {chunk.evidence_id})
            continue
        existing_revision, evidence_ids = existing
        if existing_revision != revision:
            raise RagIndexConfigurationError(
                "RAG index batch contains multiple revisions for the same source and corpus."
            )
        evidence_ids.add(chunk.evidence_id)

    groups: list[RevisionReconciliationGroup] = []
    for (tenant_id, source_ref, corpus_id), (revision, evidence_ids) in sorted(
        revisions.items()
    ):
        groups.append(
            RevisionReconciliationGroup(
                tenant_id=tenant_id,
                source_ref=source_ref,
                corpus_id=corpus_id,
                document_revision=revision,
                evidence_ids=tuple(sorted(evidence_ids)),
            )
        )
    return groups


def _hybrid_write_lock_keys(chunks: Sequence[RagChunk]) -> list[str]:
    keys: set[str] = set()
    for chunk in chunks:
        keys.add(hybrid_tenant_lifecycle_lock_key(chunk.tenant_id))
        corpus_id = chunk.metadata.get(CORPUS_ID_METADATA_KEY)
        normalized_corpus = (
            corpus_id.strip()
            if isinstance(corpus_id, str) and corpus_id.strip()
            else ""
        )
        keys.add(
            json.dumps(
                [chunk.tenant_id, chunk.source_ref, normalized_corpus],
                separators=(",", ":"),
            )
        )
    return sorted(keys)


def hybrid_tenant_lifecycle_lock_key(tenant_id: str) -> str:
    _validate_tenant_id(tenant_id)
    return json.dumps([tenant_id, "__tenant_lifecycle__"], separators=(",", ":"))


def _opensearch_reconciliation_query(
    group: RevisionReconciliationGroup,
) -> dict[str, object]:
    return {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"tenant_id": group.tenant_id}},
                    {"term": {"source_ref": group.source_ref}},
                    {"term": {CORPUS_ID_METADATA_KEY: group.corpus_id}},
                ],
                "must_not": [
                    {
                        "bool": {
                            "filter": [
                                {
                                    "term": {
                                        DOCUMENT_REVISION_METADATA_KEY: group.document_revision
                                    }
                                },
                                {"terms": {"evidence_id": list(group.evidence_ids)}},
                            ]
                        }
                    }
                ],
            }
        }
    }


def _raise_for_opensearch_reconciliation_errors(
    response: Mapping[str, object],
) -> None:
    failures = response.get("failures")
    conflicts = response.get("version_conflicts")
    if (
        response.get("timed_out") is not False
        or not isinstance(conflicts, int)
        or isinstance(conflicts, bool)
        or conflicts != 0
        or (
            isinstance(failures, Sequence)
            and not isinstance(failures, (str, bytes, bytearray))
            and bool(failures)
        )
        or failures is None
        or not isinstance(failures, Sequence)
        or isinstance(failures, (str, bytes, bytearray))
    ):
        raise RagIndexTransportError("OpenSearch revision reconciliation failed.")


def _raise_for_opensearch_lifecycle_deletion_errors(
    response: Mapping[str, object],
) -> None:
    failures = response.get("failures")
    conflicts = response.get("version_conflicts")
    deleted = response.get("deleted")
    if (
        response.get("timed_out") is not False
        or not isinstance(conflicts, int)
        or isinstance(conflicts, bool)
        or conflicts != 0
        or not isinstance(deleted, int)
        or isinstance(deleted, bool)
        or deleted < 0
        or not isinstance(failures, Sequence)
        or isinstance(failures, (str, bytes, bytearray))
        or bool(failures)
        or "error" in response
    ):
        raise RagIndexTransportError("OpenSearch lifecycle deletion failed.")


def _validate_opensearch_health_response(
    response: Mapping[str, object],
    *,
    require_green: bool,
    minimum_data_nodes: int,
) -> None:
    status = response.get("status")
    data_nodes = response.get("number_of_data_nodes")
    if (
        status not in ({"green"} if require_green else {"green", "yellow"})
        or response.get("timed_out") is not False
        or not isinstance(data_nodes, int)
        or isinstance(data_nodes, bool)
        or data_nodes < minimum_data_nodes
        or "error" in response
    ):
        raise RagIndexTransportError("OpenSearch cluster is not ready.")


def _validated_exact_lookup_ids(
    tenant_id: str,
    evidence_ids: Sequence[str],
) -> list[str]:
    _validate_tenant_id(tenant_id)
    if len(evidence_ids) > MAX_EXACT_LOOKUP_IDS:
        raise RagIndexConfigurationError("Exact RAG lookup exceeded its bounded batch size.")
    normalized: list[str] = []
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            raise RagIndexConfigurationError("Exact RAG lookup IDs must be non-empty strings.")
        if evidence_id in normalized:
            raise RagIndexConfigurationError("Exact RAG lookup IDs must be unique.")
        normalized.append(evidence_id)
    return sorted(normalized)


def _validate_exact_lookup_response(
    evidence: Sequence[Evidence],
    requested_ids: Sequence[str],
    *,
    backend_name: str,
) -> None:
    observed: set[str] = set()
    expected = set(requested_ids)
    for item in evidence:
        if item.evidence_id not in expected or item.evidence_id in observed:
            raise RagIndexTransportError(
                f"{backend_name} exact lookup returned invalid evidence IDs."
            )
        observed.add(item.evidence_id)


def _validate_hybrid_write_result(
    result: RagIndexWriteResult,
    *,
    expected_ids: Sequence[str],
    expected_backend: str,
) -> None:
    if (
        result.backend != expected_backend
        or result.indexed_count != len(expected_ids)
        or result.evidence_ids != list(expected_ids)
    ):
        raise RagIndexTransportError("Hybrid RAG backend reported an inconsistent write.")


def _validate_evidence_tenant_trace(evidence: Evidence, tenant_id: str) -> None:
    retrieval = _retrieval_mapping(evidence)
    if retrieval.get("tenant_id") != tenant_id or retrieval.get("tenant_scoped") is not True:
        raise RagIndexTransportError("Persistent RAG evidence tenant trace is invalid.")


def _retrieval_mapping(evidence: Evidence) -> dict[str, object]:
    retrieval = evidence.structured_content.get("retrieval")
    if not isinstance(retrieval, Mapping):
        raise RagIndexTransportError("Persistent RAG evidence is missing retrieval trace.")
    return dict(retrieval)


def _finite_score(value: object) -> float:
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        raise RagIndexTransportError("Persistent RAG ranker returned an invalid score.")
    return float(value)


def _assert_canonical_evidence_match(
    left: Evidence,
    right: Evidence,
    *,
    tenant_id: str,
) -> None:
    _validate_evidence_tenant_trace(left, tenant_id)
    _validate_evidence_tenant_trace(right, tenant_id)
    if _canonical_evidence(left) != _canonical_evidence(right):
        raise RagIndexTransportError(
            "Persistent RAG backends disagree on canonical evidence content."
        )


def _canonical_evidence(evidence: Evidence) -> tuple[object, ...]:
    metadata = evidence.structured_content.get("metadata")
    if not isinstance(metadata, Mapping):
        raise RagIndexTransportError("Persistent RAG evidence metadata is invalid.")
    try:
        canonical_metadata = canonical_json(metadata)
    except RagMetadataValidationError:
        raise RagIndexTransportError("Persistent RAG evidence metadata is invalid.") from None
    published_at = evidence.freshness.published_at
    return (
        evidence.evidence_id,
        evidence.kind,
        evidence.source_ref,
        evidence.content,
        evidence.authority,
        evidence.freshness.retrieved_at.isoformat(),
        published_at.isoformat() if published_at is not None else None,
        evidence.freshness.staleness_class,
        canonical_metadata,
    )


def _with_hybrid_retrieval_trace(
    evidence: Evidence,
    *,
    claim_id: str,
    tenant_id: str,
    opensearch: _RankObservation | None,
    pgvector: _RankObservation | None,
) -> tuple[Evidence, float, float]:
    observations = {
        HYBRID_OPENSEARCH_RANKER: _rank_observation_trace(opensearch),
        HYBRID_PGVECTOR_RANKER: _rank_observation_trace(pgvector),
    }
    rrf_score = sum(
        1.0 / (HYBRID_RRF_K + observation.rank)
        for observation in (opensearch, pgvector)
        if observation is not None
    )
    max_rrf_score = 2.0 / (HYBRID_RRF_K + 1)
    normalized_rrf_score = min(1.0, rrf_score / max_rrf_score)
    authority_score = _authority_rerank_score(evidence.authority)
    freshness_score = _freshness_rerank_score(evidence.freshness.staleness_class)
    total_score = (
        (0.78 * normalized_rrf_score)
        + (0.14 * authority_score)
        + (0.08 * freshness_score)
    )
    retrieval = {
        "claim_id": claim_id,
        "ranker": HYBRID_RANKER,
        "tenant_id": tenant_id,
        "tenant_scoped": True,
        "rrf_k": HYBRID_RRF_K,
        "rrf_score": round(rrf_score, 8),
        "normalized_rrf_score": round(normalized_rrf_score, 6),
        "authority_score": round(authority_score, 4),
        "freshness_score": round(freshness_score, 4),
        "total_score": round(total_score, 6),
        "rankers": observations,
    }
    return (
        evidence.model_copy(
            update={
                "structured_content": {
                    **evidence.structured_content,
                    "retrieval": retrieval,
                }
            }
        ),
        total_score,
        rrf_score,
    )


def _rank_observation_trace(observation: _RankObservation | None) -> dict[str, object]:
    if observation is None:
        return {"matched": False, "rank": None, "score": None}
    return {
        "matched": True,
        "rank": observation.rank,
        "score": round(observation.score, 8),
    }


def _authority_rerank_score(authority: Authority) -> float:
    return {
        Authority.OFFICIAL: 1.0,
        Authority.INTERNAL: 0.85,
        Authority.TRUSTED_THIRD_PARTY: 0.7,
        Authority.UNKNOWN: 0.35,
    }[authority]


def _freshness_rerank_score(staleness: StalenessClass) -> float:
    return {
        StalenessClass.FRESH: 1.0,
        StalenessClass.ACCEPTABLE: 0.75,
        StalenessClass.STALE: 0.2,
        StalenessClass.UNKNOWN: 0.4,
    }[staleness]


def _advisory_unlock_succeeded(
    row: Mapping[str, object] | Sequence[object] | None,
) -> bool:
    if isinstance(row, Mapping):
        return row.get("unlocked") is True
    if isinstance(row, Sequence) and not isinstance(row, (str, bytes, bytearray)):
        return bool(row) and row[0] is True
    return False


def _validate_opensearch_authorization(authorization: SecretValue) -> None:
    value = authorization.reveal()
    if len(value) > 8192 or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise RagIndexConfigurationError("OpenSearch authorization secret is invalid.")
    scheme, separator, credential = value.partition(" ")
    if (
        separator != " "
        or scheme not in {"Basic", "Bearer", "ApiKey"}
        or not credential
        or credential != credential.strip()
        or re.fullmatch(r"[A-Za-z0-9._~+/=-]+", credential) is None
    ):
        raise RagIndexConfigurationError("OpenSearch authorization secret is invalid.")


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
    _validate_configuration_text(search_request.claim_id, "claim_id")
    _validate_configuration_text(search_request.query_text, "query_text")
    for context_ref in search_request.context_refs:
        _validate_configuration_text(context_ref, "context_ref")
    if search_request.max_results <= 0:
        raise RagIndexConfigurationError("max_results must be positive")
    try:
        validate_metadata_filter(search_request.metadata_filter)
    except RagMetadataValidationError as exc:
        raise RagIndexConfigurationError(str(exc)) from None


def _ensure_single_tenant(chunks: Sequence[RagChunk]) -> None:
    tenant_ids = {chunk.tenant_id for chunk in chunks}
    if len(tenant_ids) != 1:
        raise RagIndexConfigurationError("RAG index writes must contain exactly one tenant")
    for chunk in chunks:
        _validate_tenant_id(chunk.tenant_id)
        _validate_configuration_text(chunk.evidence_id, "evidence_id")
        _validate_configuration_text(chunk.source_ref, "source_ref")
        _validate_configuration_text(chunk.content, "content")


def _validate_tenant_id(tenant_id: str) -> None:
    _validate_configuration_text(tenant_id, "tenant_id")


def _validate_configuration_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RagIndexConfigurationError(f"{field_name} must be non-empty")
    try:
        return validate_persistable_text(value)
    except RagMetadataValidationError:
        raise RagIndexConfigurationError(f"{field_name} contains invalid Unicode") from None


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
    settings = template_body.get("settings")
    if not isinstance(settings, Mapping):
        raise RagIndexConfigurationError("OpenSearch template settings must be an object")
    metadata = template.get("_meta")
    if (
        not isinstance(metadata, Mapping)
        or metadata.get("schema_version") != OPENSEARCH_TEMPLATE_SCHEMA_VERSION
    ):
        raise RagIndexConfigurationError(
            "OpenSearch template must declare schema version v3."
        )
    _validate_opensearch_replica_settings(settings)
    _validate_opensearch_schema_mappings(mappings, configuration_error=True)


def _validate_installed_opensearch_template(
    response: Mapping[str, object],
    *,
    template_name: str,
    index_name: str,
) -> None:
    raw_templates = response.get("index_templates")
    if not isinstance(raw_templates, Sequence) or isinstance(
        raw_templates, (str, bytes, bytearray)
    ):
        raise RagIndexTransportError("OpenSearch template readback was invalid.")
    matching: list[Mapping[str, object]] = []
    for item in raw_templates:
        if isinstance(item, Mapping) and item.get("name") == template_name:
            matching.append(item)
    if len(matching) != 1:
        raise RagIndexTransportError("OpenSearch template readback was invalid.")
    installed = matching[0].get("index_template")
    try:
        if not isinstance(installed, Mapping):
            raise RagIndexConfigurationError("installed template is missing")
        _validate_opensearch_template_payload(installed)
        _validate_opensearch_template_targets_index(
            installed,
            index_name=index_name,
        )
    except RagIndexConfigurationError:
        raise RagIndexTransportError(
            "OpenSearch installed template is not schema v3."
        ) from None


def _validate_existing_opensearch_index_mapping(
    response: Mapping[str, object],
    *,
    index_name: str,
) -> str:
    if not response:
        return "absent"
    index_payload = response.get(index_name)
    if not isinstance(index_payload, Mapping):
        raise RagIndexTransportError(
            "OpenSearch existing index is incompatible; create and reindex into a schema v3 index."
        )
    mappings = index_payload.get("mappings")
    try:
        if not isinstance(mappings, Mapping):
            raise RagIndexConfigurationError("existing mappings are missing")
        _validate_opensearch_schema_mappings(mappings, configuration_error=False)
    except RagIndexConfigurationError:
        raise RagIndexTransportError(
            "OpenSearch existing index is incompatible; create and reindex into a schema v3 index."
        ) from None
    return "compatible"


def _validate_existing_opensearch_index_settings(
    response: Mapping[str, object],
    *,
    index_name: str,
) -> None:
    index_payload = response.get(index_name)
    settings = index_payload.get("settings") if isinstance(index_payload, Mapping) else None
    try:
        if not isinstance(settings, Mapping):
            raise RagIndexConfigurationError("existing index settings are missing")
        _validate_opensearch_replica_settings(settings)
    except RagIndexConfigurationError:
        raise RagIndexTransportError(
            "OpenSearch existing index must have at least one replica before schema v3 startup."
        ) from None


def _validate_opensearch_replica_settings(settings: Mapping[str, object]) -> None:
    raw_value: object = settings.get("number_of_replicas")
    if raw_value is None:
        raw_value = settings.get("index.number_of_replicas")
    nested_index = settings.get("index")
    if raw_value is None and isinstance(nested_index, Mapping):
        raw_value = nested_index.get("number_of_replicas")
    if isinstance(raw_value, str) and raw_value.isdecimal():
        replica_count = int(raw_value)
    elif isinstance(raw_value, int) and not isinstance(raw_value, bool):
        replica_count = raw_value
    else:
        replica_count = -1
    if replica_count < 1:
        raise RagIndexConfigurationError(
            "OpenSearch schema v3 requires number_of_replicas >= 1."
        )


def _validate_opensearch_template_targets_index(
    template: Mapping[str, object],
    *,
    index_name: str,
) -> None:
    raw_patterns = template.get("index_patterns")
    if not isinstance(raw_patterns, Sequence) or isinstance(
        raw_patterns, (str, bytes, bytearray)
    ):
        raise RagIndexConfigurationError("OpenSearch template index patterns are invalid.")
    patterns = [item for item in raw_patterns if isinstance(item, str)]
    if not any(_opensearch_index_pattern_matches(pattern, index_name) for pattern in patterns):
        raise RagIndexConfigurationError(
            "OpenSearch template does not target the configured evidence index."
        )


def _opensearch_index_pattern_matches(pattern: str, index_name: str) -> bool:
    expression = "".join(
        ".*" if character == "*" else "." if character == "?" else re.escape(character)
        for character in pattern
    )
    return re.fullmatch(expression, index_name) is not None


def _validate_opensearch_schema_mappings(
    mappings: Mapping[str, object],
    *,
    configuration_error: bool,
) -> None:
    metadata = mappings.get("_meta")
    properties = mappings.get("properties")
    dynamic = mappings.get("dynamic")
    dynamic_is_disabled = dynamic is False or (
        not configuration_error and dynamic == "false"
    )
    valid = (
        isinstance(metadata, Mapping)
        and metadata.get("schema_version") == OPENSEARCH_TEMPLATE_SCHEMA_VERSION
        and isinstance(properties, Mapping)
        and dynamic_is_disabled
    )
    if valid:
        assert isinstance(properties, Mapping)
        for field_name in (
            "tenant_id",
            "evidence_id",
            "source_ref",
            CORPUS_ID_METADATA_KEY,
            DOCUMENT_REVISION_METADATA_KEY,
            "metadata_filter_tokens",
        ):
            field_mapping = properties.get(field_name)
            if not isinstance(field_mapping, Mapping) or field_mapping.get("type") != "keyword":
                valid = False
                break
        metadata_mapping = properties.get("metadata")
        if (
            not isinstance(metadata_mapping, Mapping)
            or metadata_mapping.get("type") != "object"
            or metadata_mapping.get("enabled") is not False
        ):
            valid = False
    if not valid:
        if configuration_error:
            raise RagIndexConfigurationError(
                "OpenSearch schema v3 requires fixed tenant/control/token fields and disabled metadata."
            )
        raise RagIndexConfigurationError("OpenSearch existing index mapping is stale.")


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
    if "freshness" in source:
        freshness = source.get("freshness")
        if not isinstance(freshness, Mapping):
            raise RagIndexTransportError("Persistent RAG freshness object is invalid.")
        return Freshness(
            retrieved_at=_required_datetime(
                freshness.get("retrieved_at"),
                "freshness.retrieved_at",
            ),
            published_at=_optional_datetime(
                freshness.get("published_at"),
                "freshness.published_at",
            ),
            staleness_class=_staleness_from_value(freshness.get("staleness_class")),
        )
    return Freshness(
        retrieved_at=_required_datetime(source.get("retrieved_at"), "retrieved_at"),
        published_at=_optional_datetime(source.get("published_at"), "published_at"),
        staleness_class=_staleness_from_value(source.get("staleness_class")),
    )


def _required_datetime(value: object, field_name: str) -> datetime:
    parsed = _parse_datetime_value(value)
    if parsed is None:
        raise RagIndexTransportError(
            f"Persistent RAG {field_name} must be a timezone-aware datetime."
        )
    return parsed


def _optional_datetime(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    parsed = _parse_datetime_value(value)
    if parsed is None:
        raise RagIndexTransportError(
            f"Persistent RAG {field_name} must be null or a timezone-aware datetime."
        )
    return parsed


def _parse_datetime_value(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    try:
        return parsed if parsed.utcoffset() is not None else None
    except (OverflowError, ValueError):
        return None


def _authority_from_value(value: object) -> Authority:
    if isinstance(value, str):
        try:
            return Authority(value)
        except ValueError:
            pass
    raise RagIndexTransportError("Persistent RAG authority is invalid.")


def _staleness_from_value(value: object) -> StalenessClass:
    if isinstance(value, str):
        try:
            return StalenessClass(value)
        except ValueError:
            pass
    raise RagIndexTransportError("Persistent RAG staleness_class is invalid.")


def _required_string(value: object, field_name: str) -> str:
    if isinstance(value, str) and value.strip():
        try:
            return validate_persistable_text(value)
        except RagMetadataValidationError:
            pass
    raise RagIndexTransportError(f"RAG index result missing non-empty {field_name}")
