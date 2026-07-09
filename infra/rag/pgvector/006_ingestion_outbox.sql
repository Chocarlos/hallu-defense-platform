-- Ingestion outbox: durable job queue for async document ingestion/reindex.
-- Idempotent (IF NOT EXISTS everywhere) so the applier can re-run it safely.

CREATE TABLE IF NOT EXISTS rag_ingestion_jobs (
    job_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    corpus_id text,
    trace_id text NOT NULL,
    job_type text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    locked_by text,
    locked_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_rag_ingestion_jobs_status_available
    ON rag_ingestion_jobs (status, available_at);

CREATE INDEX IF NOT EXISTS ix_rag_ingestion_jobs_tenant
    ON rag_ingestion_jobs (tenant_id);
