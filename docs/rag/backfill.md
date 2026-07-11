# RAG Backfill And Async Ingestion

Local/test development keeps document ingestion synchronous by default:

```text
HALLU_DEFENSE_INGESTION_MODE=sync
```

Production and staging reject that setting and require
`HALLU_DEFENSE_INGESTION_MODE=async`. Use async mode only when
`HALLU_DEFENSE_POSTGRES_DSN` points at a migrated PostgreSQL database. Async
mode fails closed without Postgres because the ingestion outbox is the durable
source of truth for queued, running, retried, succeeded, and dead-lettered
jobs.

The enqueue path still runs the existing tenant, corpus, metadata, ABAC/grant,
and writer-role checks before writing a job. The queued payload stores the
prepared document metadata, including the tenant and corpus stamps, so workers
execute the request authorized at enqueue time without reinterpreting caller
roles later.

## Worker

Run one worker pass:

```bash
python -m hallu_defense.worker --once
```

Run continuously:

```bash
python -m hallu_defense.worker
```

Worker settings:

```text
HALLU_DEFENSE_INGESTION_WORKER_ID=ingestion-worker-local
HALLU_DEFENSE_INGESTION_WORKER_POLL_SECONDS=2
HALLU_DEFENSE_INGESTION_WORKER_BATCH_SIZE=10
HALLU_DEFENSE_INGESTION_WORKER_MAX_ATTEMPTS=5
HALLU_DEFENSE_INGESTION_WORKER_BACKOFF_BASE_SECONDS=30
HALLU_DEFENSE_INGESTION_WORKER_LOCK_TIMEOUT_SECONDS=300
HALLU_DEFENSE_INGESTION_BACKFILL_PAGE_SIZE=100
```

The worker claims jobs with `FOR UPDATE SKIP LOCKED` and records
`ingestion_job_*` audit events. Deterministic payload or application failures
use exponential backoff and dead-letter after the configured max attempts.
With the hybrid backend, a transport failure may mean OpenSearch accepted a
write before PostgreSQL failed. Those jobs and jobs recovered after a worker
crash remain durable `failed` reconciliation intents instead of becoming
dead letters. They retry the two idempotent writes with an exponential delay
capped at one hour until parity is restored or the tenant-deletion tombstone
discards the work. This prevents a transient partial write from becoming a
silent, permanently orphaned index document.

## Status

Use the tenant-scoped status endpoint with the same tenant header used to
enqueue the job:

```bash
curl -sS http://localhost:8000/documents/ingest/status \
  -H 'content-type: application/json' \
  -H 'x-tenant-id: tenant-a' \
  -d '{"job_id":"ing_example"}'
```

Cross-tenant status lookups return `404`.

## Backfill safety gate

Corpus reindex is currently disabled fail-closed for every real target backend.
The CLI exits before opening PostgreSQL or enqueueing, and the worker reindexer
rejects an already queued job before reading the first source page or writing a
target. This is intentional: pgvector, OpenSearch, and hybrid writes reconcile
a complete document revision on every `index_chunks` call. Streaming a revision
across multiple pages would make each later page delete chunks written by its
siblings, even when source and target use different storage.

The gate requires all of the following before reindex can be enabled:

- explicit, non-empty storage identities for both source and every target store;
- no source/target storage-identity intersection;
- an explicit `backfill_page_safe=True` capability on the target.

No current persistent backend declares that capability. A production reindex
implementation must instead use a generational target (or equivalent staging
namespace), stream upserts into that isolated generation, verify completeness,
and atomically swap an alias/pointer under a corpus-scoped lock. Only after that
commit protocol exists may the CLI enqueue work and documentation describe
reindex reruns as idempotent.

## Live Smoke

The crash/restart ingestion worker smoke is disabled by default:

```bash
python scripts/dev/live_ingestion_worker_smoke.py
```

It runs only with:

```text
HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED=true
```

The enabled smoke is restricted to a local or test runtime and requires a
loopback PostgreSQL URL with permission to create databases. It creates a
randomly named scratch database, applies every migration there, and drops it
on both success and failure. It never applies, repairs, or otherwise changes
the main database migration ledger. Cleanup also closes the connection pool
before the database drop and checks that the scratch database no longer
exists.

This is a real process crash/recovery proof:

1. The controller enqueues one document, then holds the same session-level
   PostgreSQL advisory lock used by the pgvector revision writer.
2. Worker A runs as `python -m hallu_defense.worker --once`. The smoke observes
   its `RUNNING` row, lease token, and `pg_stat_activity` advisory-lock wait
   before killing it. On Linux that `kill()` is SIGKILL, and a zero exit status
   fails the smoke.
3. The controller leaves the job untouched and waits until the lease deadline
   has passed according to the real PostgreSQL clock. Only then does Worker B
   start with the same worker id, reclaim the job, and receive a new fencing
   token.
4. While Worker B still owns the lease, the smoke proves that the old token
   cannot perform heartbeat, completion, and failure transitions. It then
   releases the pgvector barrier and requires Worker B to exit successfully.
5. The final assertions require exactly one chunk, tenant-correct retrieval,
   empty cross-tenant retrieval, one job, and exactly one terminal success
   audit event. Exact tenant/trace/run cleanup must leave no footprint.

Worker processes have fixed argv, bounded timeouts and output capture, and a
minimal allowlisted environment. The DSN is passed only through the child
environment; the DSN, document payload, and lease tokens are never included
in argv or emitted by the smoke result/error path.

`.github/workflows/live.yml` runs this smoke as a mandatory job against an
isolated Compose project. Its teardown stops and removes only that job's
PostgreSQL service, exact project volume, and exact project network; it does
not use a global `docker compose down -v`, so existing developer services and
volumes remain untouched.
