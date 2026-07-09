-- Approval queue persistence: approval records and single-use execution grants.
-- Idempotent (IF NOT EXISTS everywhere) so the applier can re-run it safely.

CREATE TABLE IF NOT EXISTS approval_records (
    approval_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    trace_id text NOT NULL,
    status text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz
);

CREATE INDEX IF NOT EXISTS ix_approval_records_tenant_status
    ON approval_records (tenant_id, status);

CREATE TABLE IF NOT EXISTS approval_execution_grants (
    token_hash text PRIMARY KEY,
    approval_id text NOT NULL,
    tenant_id text NOT NULL,
    tool_call_fingerprint text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_approval_grants_tenant_approval
    ON approval_execution_grants (tenant_id, approval_id);
