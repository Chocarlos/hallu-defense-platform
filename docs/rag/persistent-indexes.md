# Persistent RAG Indexes

The API now has a persistent RAG index boundary in
`apps/api/src/hallu_defense/services/rag_index.py`.

Current runtime default:

- `HALLU_DEFENSE_RAG_INDEX_BACKEND=local`
- Inline documents continue to use the deterministic local hybrid ranker.
- External stores are opt-in so local tests and smoke runs remain network-free.
- `docker-compose.yml` opts the API and worker into
  `HALLU_DEFENSE_RAG_INDEX_BACKEND=hybrid` for the local service topology.

Supported adapter boundaries:

- `OpenSearchRagIndexBackend`
  - Builds tenant-scoped bulk index operations.
  - Builds BM25-style `_search` requests with `tenant_id`, `context_refs`, and
    exact SHA-256 filter tokens over canonical top-level metadata JSON.
  - Fails closed if a hit's `_source.tenant_id` does not match the request tenant.
- `PgVectorRagIndexBackend`
  - Builds parameterized insert/upsert calls for chunk embeddings.
  - Builds parameterized exact vector search with `tenant_id`, optional source
    refs, a GIN-eligible containment prefilter, and mandatory top-level JSONB
    equality for metadata.
  - Rejects unsafe table identifiers before query construction.
- `HybridRagIndexBackend`
  - Writes OpenSearch first and pgvector second under a bounded PostgreSQL
    advisory lock scoped to tenant/source/corpus.
  - Fetches the union of both top-K sets by exact ID from both stores, rejects
    missing or canonically different records, and applies deterministic RRF plus
    authority/freshness reranking.
  - Reconciles stale document revisions without crossing tenant, corpus, or source
    boundaries and fails closed if either ranker or exact lookup fails.

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
HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME=rag/opensearch/authorization
# Optional for private PKI; omit to use the platform trust store.
HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH=/etc/hallu-defense/opensearch/ca.crt
HALLU_DEFENSE_POSTGRES_DSN=postgresql://hallu:hallu@localhost:5432/hallu_defense
HALLU_DEFENSE_PGVECTOR_TABLE_NAME=rag_evidence_chunks
HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION=16
```

`local` remains the default runtime backend. OpenSearch has a stdlib HTTP
transport. pgvector has a synchronous psycopg runtime connection adapter behind
`create_rag_index_backend()` when `HALLU_DEFENSE_POSTGRES_DSN` is configured,
and still fails closed on missing DSN, missing psycopg, unsafe table names, or
embedding dimensions that do not match the committed `VECTOR(16)` migration.

The committed 16-dimensional embedder is a deterministic local
lexical-vector baseline: it tokenizes normalized text, applies signed feature
hashing to the bag of tokens, and L2-normalizes the vector. It preserves lexical
overlap and is useful for offline/dev operation, but it is not a semantic
embedding model and must not be represented as equivalent to provider-generated
embeddings. A future semantic adapter must retain the provider boundary and the
same tenant/exact-lookup fail-closed rules.

## Runtime Artifacts

- `infra/rag/pgvector/001_rag_evidence_chunks.sql` creates the `vector` extension,
  `rag_evidence_chunks` table, `(tenant_id, evidence_id)` primary key, metadata GIN
  index, tenant/source index, and the historical vector cosine index.
- `infra/rag/pgvector/009_drop_unsafe_ivfflat.sql` removes that historical
  IVFFlat index without editing applied migration `001`; exact filtered recall
  is the committed correctness baseline.
- `infra/rag/pgvector/010_add_retrieved_at.sql` adds and backfills the required
  timezone-aware retrieval timestamp before enforcing `NOT NULL`; persistent
  reads never synthesize freshness.
- `infra/rag/pgvector/011_rag_lifecycle_outbox.sql` adds the transactional
  lifecycle outbox used to coordinate hybrid-store deletion convergence.
- `infra/rag/pgvector/012_rag_tenant_deletion_fence.sql` persists tenant
  erasure tombstones and rejects later evidence/job writes for those tenants.
- `infra/rag/pgvector/013_audit_history_integrity.sql` makes tenant event IDs
  unique and indexes event-type/trace keyset history reads.
- `infra/rag/opensearch/evidence-index-template.json` defines the
  `hallu_evidence*` template with `dynamic: false`, keyword tenant/source fields,
  analyzed content, top-level keyword `corpus_id` and `document_revision`,
  keyword `metadata_filter_tokens`, opaque `metadata` with `enabled: false`, one
  replica, and schema v3 metadata on both the template and concrete mapping.
- `docker-compose.yml` includes pinned local services, configures API/worker for
  hybrid persistence, and blocks both on the successful one-shot
  `opensearch-bootstrap` service.
- `scripts/ci/check_rag_persistence_config.py` validates these artifacts, Compose
  backend wiring, Makefile wiring, and CI/security workflow wiring.
- `scripts/dev/bootstrap_opensearch_template.py` installs the OpenSearch index
  template with `PUT /_index_template/hallu_evidence_template`. Its `--dry-run`
  mode validates the same local template without contacting OpenSearch.
- `scripts/dev/live_pgvector_rag_smoke.py` exercises `PgVectorRagIndexBackend`
  with the same psycopg-backed connection adapter used by the runtime factory.
- `scripts/dev/apply_postgres_migrations.py` applies all fourteen ordered migrations
  under one transaction and advisory lock with SHA-256 drift detection. The
  invariant and wiring contract is documented in `docs/rag/postgres-migrations.md`
  and enforced by `scripts/ci/check_postgres_migrations.py`.

## OpenSearch Bootstrap

```text
python scripts/dev/bootstrap_opensearch_template.py --dry-run
python scripts/dev/bootstrap_opensearch_template.py
```

The dry-run command is wired into `Makefile`, CI, and security CI. Runtime
provisioning is automatic in Compose and Helm before API/worker startup. It uses
the same validated endpoint, outbound allowlist, Vault-backed Authorization
header, and optional CA as the application. Provisioning requires an acknowledged
PUT, reads the installed template back, and verifies schema v3 plus
`number_of_replicas >= 1`. If the configured index already exists, its fixed
tenant/control/token mappings, opaque metadata mapping, and effective replica
setting must be v3-compatible. Updating a template does not migrate an existing
v1/v2 index: provisioning fails with a create-and-reindex instruction instead of
pretending an in-place upgrade occurred.

### Schema v2 to v3 operator path

The `metadata` mapping cannot be converted safely in place. Pause ingestion,
choose a new physical index name such as `hallu_evidence_v3_20260710`, install
the v3 template for that configured name, and run the PostgreSQL-backed corpus
backfill with an OpenSearch target and the new index name. Verify tenant/corpus
counts, exact evidence IDs, canonical source/metadata parity, exact metadata
filters, and revision reconciliation before switching the API and worker
`HALLU_DEFENSE_OPENSEARCH_INDEX_NAME` together. Keep v2 read-only for the
rollback window. Bootstrap must not delete the old index or attempt an unsafe
in-place/alias cutover.

Schema v3 stores arbitrary bounded metadata only in `_source`; it never creates
metadata subfield mappings. Search filters allow at most eight safe top-level
keys, 512 canonical UTF-8 bytes per value, and 2 KiB total. Ingested metadata is
limited to 32 top-level keys, 16 KiB canonical UTF-8, depth four, 256 JSON nodes,
finite numbers, and signed 64-bit integers. Callers cannot override
server-managed corpus, revision, tenant-owner, or structural keys.

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
- The local Compose service uses `opensearchproject/opensearch:2.19.5` pinned by
  an immutable multi-architecture manifest-list digest,
  single-node discovery, disabled security, and the local-only bootstrap password
  from `docker-compose.yml`. With one replica this development cluster is
  expected to be yellow: local/Kind health accepts yellow or green with at least
  one data node, while external production/staging requires green with at least
  two data nodes.

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
column, verifies that migration `009` removed all ANN indexes, checks the real
production query plan, indexes synthetic tenant A/B documents, and compares
tenant/metadata-filtered results with a direct exact oracle. It then asserts
tenant isolation and cleans up only rows tagged for the current smoke run. It
does not create, drop, truncate, or delete tables or databases.

Current local prerequisites:

- Docker Desktop or Docker Engine must be running.
- Start the local Postgres/pgvector service from the committed Compose topology:
  `docker compose up -d postgres`.
- Migrations `infra/rag/pgvector/001_rag_evidence_chunks.sql` through
  `010_add_retrieved_at.sql` must have run
  for the target database. Compose applies it when the Postgres volume is first
  initialized.
- The local Compose service uses `pgvector/pgvector:pg16` with the local-only
  `hallu` user, password, and database from `docker-compose.yml`.

## Combined Hybrid RAG Smoke

The authoritative dual-store smoke is opt-in and lives at
`scripts/dev/live_hybrid_rag_smoke.py`:

```text
HALLU_DEFENSE_LIVE_HYBRID_RAG_SMOKE_ENABLED=true \
HALLU_DEFENSE_LIVE_HYBRID_RAG_ADMIN_DSN=postgresql://admin@localhost/postgres \
HALLU_DEFENSE_OPENSEARCH_ENDPOINT=http://localhost:9200 \
make rag-hybrid-live-smoke
```

The admin DSN is used only to create a random scratch database. The smoke applies
all twelve migrations there; it never applies migrations to the main
`hallu_defense` database. It also creates an exact, random OpenSearch index and
template in the dedicated `hallu_evidence_hybrid_smoke_*` namespace. A `finally`
path drops the scratch database with `FORCE` and deletes only those exact
OpenSearch resources.

The smoke writes tenant A and tenant B through the real hybrid backend, proves
that both BM25 and cosine rankers participated in the fused RRF trace, advances
tenant A to a new document revision, and verifies both that tenant A's stale
chunks were removed and tenant B's old revision survived. Its provisioning pass
also proves the exact template targets the smoke index and that the created index
has schema v3. The admin DSN and credentials are never included in its JSON
result. This smoke runs in the live workflow, not default CI/security gates.

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
DSN redaction, absence of ANN indexes, exact-plan/filtered-recall parity, and
row-only cleanup without Docker.

`apps/api/tests/test_live_hybrid_rag_smoke.py` verifies scratch namespaces,
bounded admin connections, eleven-migration isolation, fusion/tenant/revision
assertions, and database/index/template cleanup without starting Docker.

`apps/api/tests/test_rag_persistence_config.py` verifies the runtime artifacts fail closed
when tenant isolation, pinned images, bootstrap dry-run wiring, live smoke wiring, or CI
wiring are removed.

## Current Limits

OpenSearch, pgvector, and their combined hybrid path have opt-in live smokes for
local validation, but they are intentionally not part of default CI because they
require Docker-backed services.
Managed-service load/HA validation, provider-operated migration scheduling, and
integration tests against managed services remain deployment work.
