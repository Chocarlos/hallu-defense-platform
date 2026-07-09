# RAG Backfill And Async Ingestion

Batch 6 keeps document ingestion synchronous by default:

```text
HALLU_DEFENSE_INGESTION_MODE=sync
```

Set `HALLU_DEFENSE_INGESTION_MODE=async` only when
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

The worker claims jobs with `FOR UPDATE SKIP LOCKED`, records
`ingestion_job_*` audit events, retries failures with exponential backoff, and
dead-letters after the configured max attempts.

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

## Backfill

Enqueue a corpus reindex job:

```bash
python scripts/dev/run_rag_backfill.py \
  --tenant-id tenant-a \
  --corpus-id default
```

Optionally process one batch inline after enqueue:

```bash
python scripts/dev/run_rag_backfill.py \
  --tenant-id tenant-a \
  --corpus-id default \
  --run-worker-once
```

Backfill reads source chunks by tenant and `metadata.corpus_id`, then reindexes
them through the configured target backend using the existing stable
`evidence_id` natural key. Pgvector uses `ON CONFLICT (tenant_id, evidence_id)
DO UPDATE`, so rerunning a reindex is idempotent.

## Live Smoke

The live ingestion worker smoke is disabled by default:

```bash
python scripts/dev/live_ingestion_worker_smoke.py
```

It runs only with:

```text
HALLU_DEFENSE_LIVE_INGESTION_WORKER_SMOKE_ENABLED=true
```

The enabled smoke requires Compose Postgres/pgvector, applies migrations,
simulates a stale claimed job, verifies worker recovery, repeats ingestion to
prove idempotent upsert behavior, checks tenant-scoped retrieval, and removes
only the smoke rows for the generated run id.
