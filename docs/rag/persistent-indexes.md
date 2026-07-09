# Persistent RAG Indexes

The API now has a persistent RAG index boundary in
`apps/api/src/hallu_defense/services/rag_index.py`.

Current runtime default:

- `HALLU_DEFENSE_RAG_INDEX_BACKEND=local`
- Inline documents continue to use the deterministic local hybrid ranker.
- External stores are opt-in so local tests and smoke runs remain network-free.
- `docker-compose.yml` opts the API into `HALLU_DEFENSE_RAG_INDEX_BACKEND=opensearch`
  for the local service topology.

Supported adapter boundaries:

- `OpenSearchRagIndexBackend`
  - Builds tenant-scoped bulk index operations.
  - Builds BM25-style `_search` requests with `tenant_id`, `context_refs`, and exact metadata filters.
  - Drops search hits whose `_source.tenant_id` does not match the request tenant.
- `PgVectorRagIndexBackend`
  - Builds parameterized insert/upsert calls for chunk embeddings.
  - Builds parameterized vector search with `tenant_id`, optional source refs, and metadata JSON filters.
  - Rejects unsafe table identifiers before query construction.

`HybridRetriever` accepts an optional `RagIndexBackend`. When a backend is present,
`/evidence/retrieve` passes the request tenant, `context_refs`, and `metadata_filter`
into persistent search and merges persistent hits with inline local evidence.

`POST /documents/ingest` is the public ingestion surface. It validates `DocumentInput`
payloads, adds `corpus_id` metadata, uses the request tenant from `x-tenant-id`, and
returns `trace_id`, backend, document count, indexed count, indexed evidence IDs, and
warnings. With the default `local` backend it returns a warning instead of pretending
that documents were persisted.

## Configuration

```text
HALLU_DEFENSE_RAG_INDEX_BACKEND=local
HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS=5
HALLU_DEFENSE_OPENSEARCH_ENDPOINT=http://localhost:9200
HALLU_DEFENSE_OPENSEARCH_INDEX_NAME=hallu_evidence
HALLU_DEFENSE_PGVECTOR_TABLE_NAME=rag_evidence_chunks
HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION=16
```

`local` is the only fully wired runtime backend. OpenSearch has a stdlib HTTP
transport; pgvector requires an injected database connection and is intentionally
fail-closed through `create_rag_index_backend()` until runtime connection wiring
exists.

## Runtime Artifacts

- `infra/rag/pgvector/001_rag_evidence_chunks.sql` creates the `vector` extension,
  `rag_evidence_chunks` table, `(tenant_id, evidence_id)` primary key, metadata GIN
  index, tenant/source index, and vector cosine index.
- `infra/rag/opensearch/evidence-index-template.json` defines the
  `hallu_evidence*` template with `dynamic: false`, keyword tenant/source fields,
  analyzed content, metadata object support, and `_meta.required_query_filter=tenant_id`.
- `docker-compose.yml` includes a pinned local OpenSearch service, configures the API
  to use it for persistent RAG indexing, and mounts the pgvector migration into
  Postgres initialization.
- `scripts/ci/check_rag_persistence_config.py` validates these artifacts, Compose
  backend wiring, Makefile wiring, and CI/security workflow wiring.
- `scripts/dev/bootstrap_opensearch_template.py` installs the OpenSearch index
  template with `PUT /_index_template/hallu_evidence_template`. Its `--dry-run`
  mode validates the same local template without contacting OpenSearch.

## OpenSearch Bootstrap

```text
python scripts/dev/bootstrap_opensearch_template.py --dry-run
python scripts/dev/bootstrap_opensearch_template.py
```

The dry-run command is wired into `Makefile`, CI, and security CI. The non-dry-run
command requires a reachable OpenSearch endpoint from `HALLU_DEFENSE_OPENSEARCH_ENDPOINT`
or `--endpoint`.

## Live OpenSearch RAG Smoke

The live OpenSearch RAG smoke is opt-in. It is not part of `rag-persistence-config`,
`security-check`, CI, or security CI because it requires a running OpenSearch service.
Use it only when validating the local live-service path:

```text
HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_ENABLED=true make rag-opensearch-live-smoke
```

PowerShell equivalent:

```powershell
$env:HALLU_DEFENSE_LIVE_OPENSEARCH_RAG_SMOKE_ENABLED = 'true'
make rag-opensearch-live-smoke
```

The Makefile target runs `scripts/dev/live_opensearch_rag_smoke.py`. The smoke
installs the committed OpenSearch template, creates a validated smoke index,
indexes synthetic tenant A/B documents, refreshes/searches OpenSearch, asserts
tenant isolation, and deletes the smoke index before exiting. The default smoke
index is `hallu_evidence_live_smoke`; custom smoke indexes must remain dedicated
developer indexes such as `hallu_evidence_smoke`. Do not point this command at a
production or shared customer index.

Current local prerequisites:

- Docker Desktop or Docker Engine must be running.
- Start the local OpenSearch service from the committed Compose topology:
  `docker compose up -d opensearch`.
- OpenSearch must be reachable at `HALLU_DEFENSE_OPENSEARCH_ENDPOINT`, which
  defaults to `http://localhost:9200` for developer runs.
- The local Compose service uses `opensearchproject/opensearch:2.15.0`,
  single-node discovery, disabled security, and the local-only bootstrap password
  from `docker-compose.yml`.

## Validation

`apps/api/tests/test_rag_index_adapters.py` verifies:

- `/documents/ingest` preserves trace and tenant context,
- ingestion adds corpus metadata before indexing,
- local ingestion returns an explicit non-persistence warning,
- inline documents are transformed into tenant-scoped persistent chunks,
- `/evidence/retrieve` propagates `x-tenant-id`, `context_refs`, and metadata filters,
- OpenSearch bulk/search payloads include tenant filters,
- OpenSearch template installation builds the expected `_index_template` request,
- cross-tenant OpenSearch hits are ignored,
- pgvector SQL uses parameters for tenant, metadata, source refs, vector, and limit,
- unsafe OpenSearch index and pgvector table identifiers are rejected.

`apps/api/tests/test_opensearch_bootstrap.py` verifies dry-run behavior, acknowledged
installation behavior, and fail-closed handling when OpenSearch does not acknowledge
the template installation.

`apps/api/tests/test_rag_persistence_config.py` verifies the runtime artifacts fail closed
when tenant isolation, pinned images, bootstrap dry-run wiring, or CI wiring are removed.

## Current Limits

OpenSearch has an opt-in live smoke for local validation, but it is intentionally
not part of default CI because it requires Docker/OpenSearch. pgvector remains an
adapter and static configuration boundary only: connection pools, live migration
execution evidence, integration tests, and backfill workers remain future work.
