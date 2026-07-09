-- Audit ledger persistence: append-only runs and per-event rows.
-- Idempotent (IF NOT EXISTS everywhere) so the applier can re-run it safely.

CREATE TABLE IF NOT EXISTS audit_runs (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    trace_id text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_audit_runs_tenant_created
    ON audit_runs (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS ix_audit_runs_tenant_trace
    ON audit_runs (tenant_id, trace_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    trace_id text NOT NULL,
    event_id text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_created
    ON audit_events (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_trace
    ON audit_events (tenant_id, trace_id);
