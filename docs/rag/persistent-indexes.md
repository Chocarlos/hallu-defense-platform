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
HALLU_DEFENSE_POSTGRES_DSN=postgresql://hallu:hallu@localhost:5432/hallu_defense
HALLU_DEFENSE_PGVECTOR_TABLE_NAME=rag_evidence_chunks
HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION=16
```

`local` remains the default runtime backend. OpenSearch has a stdlib HTTP
transport. pgvector has a synchronous psycopg runtime connection adapter behind
`create_rag_index_backend()` when `HALLU_DEFENSE_POSTGRES_DSN` is configured,
and still fails closed on missing DSN, missing psycopg, unsafe table names, or
embedding dimensions that do not match the committed `VECTOR(16)` migration.

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
- `scripts/dev/live_pgvector_rag_smoke.py` exercises `PgVectorRagIndexBackend`
  with the same psycopg-backed connection adapter used by the runtime factory.

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

## Live pgvector RAG Smoke

The live pgvector RAG smoke is also opt-in. It is not part of
`rag-persistence-config`, `security-check`, CI, or security CI because it requires
a running PostgreSQL/pgvector service. Use it only when validating the local
adapter path:

```text
HALLU_DEFENSE_LIVE_PGVECTOR_RAG_SMOKE_ENABLED=true make rag-pgvector-live-smoke
```

PowerShell equivalent:

```powershell
$env:HALLU_DEFENSE_LIVE_PGVECTOR_RAG_SMOKE_ENABLED = 'true'
make rag-pgvector-live-smoke
```

The Makefile target runs `scripts/dev/live_pgvector_rag_smoke.py`. The smoke uses
the default `HALLU_DEFENSE_POSTGRES_DSN` value
`postgresql://hallu:hallu@localhost:5432/hallu_defense` and the default
`HALLU_DEFENSE_PGVECTOR_TABLE_NAME=rag_evidence_chunks`, unless those variables
are overridden. It verifies the `vector` extension and `VECTOR(16)` embedding
column, indexes synthetic tenant A/B documents through the existing ingestion
and retrieval services, asserts tenant isolation through pgvector searches, and
cleans up only rows tagged for the current smoke run. It does not create, drop,
truncate, or delete tables or databases.

Current local prerequisites:

- Docker Desktop or Docker Engine must be running.
- Start the local Postgres/pgvector service from the committed Compose topology:
  `docker compose up -d postgres`.
- The `infra/rag/pgvector/001_rag_evidence_chunks.sql` migration must have run
  for the target database. Compose applies it when the Postgres volume is first
  initialized.
- The local Compose service uses `pgvector/pgvector:pg16` with the local-only
  `hallu` user, password, and database from `docker-compose.yml`.

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

`apps/api/tests/test_live_pgvector_rag_smoke.py` verifies the pgvector smoke env
gate, safe table validation, fake-connection live path, tenant isolation checks,
DSN redaction, and row-only cleanup without Docker.

`apps/api/tests/test_rag_persistence_config.py` verifies the runtime artifacts fail closed
when tenant isolation, pinned images, bootstrap dry-run wiring, live smoke wiring, or CI
wiring are removed.

## Current Limits

OpenSearch and pgvector have opt-in live smokes for local validation, but they are
intentionally not part of default CI because they require Docker-backed services.
Managed connection pooling, repeatable migration execution in deployment,
integration tests against managed services, and backfill workers remain future
work.
