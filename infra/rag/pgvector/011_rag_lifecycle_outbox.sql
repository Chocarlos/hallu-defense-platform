-- Durable cross-store lifecycle journal for hybrid pgvector/OpenSearch deletion.

CREATE TABLE IF NOT EXISTS rag_lifecycle_operations (
    operation_id text PRIMARY KEY,
    operation_kind text NOT NULL CHECK (operation_kind IN ('retention', 'tenant_deletion')),
    target_tenant_id text,
    executed_at timestamptz NOT NULL,
    evidence_cutoff timestamptz,
    actor_id text NOT NULL,
    trace_id text NOT NULL,
    status text NOT NULL CHECK (
        status IN ('pending', 'processing', 'external_deleted', 'completed')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_token text,
    locked_at timestamptz,
    external_deleted_count bigint NOT NULL DEFAULT 0 CHECK (external_deleted_count >= 0),
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (operation_kind = 'retention' AND target_tenant_id IS NULL AND evidence_cutoff IS NOT NULL)
        OR
        (operation_kind = 'tenant_deletion' AND target_tenant_id IS NOT NULL AND evidence_cutoff IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS ix_rag_lifecycle_operations_active
    ON rag_lifecycle_operations (operation_kind, target_tenant_id, created_at)
    WHERE status IN ('pending', 'processing', 'external_deleted');
