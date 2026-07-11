-- Durable privacy fence for tenants whose data-deletion workflow completed.
-- The tombstone is intentionally not part of retention/deletion table sweeps.

CREATE TABLE IF NOT EXISTS rag_tenant_deletion_tombstones (
    tenant_id text PRIMARY KEY,
    operation_id text NOT NULL REFERENCES rag_lifecycle_operations (operation_id),
    deleted_at timestamptz NOT NULL,
    actor_id text NOT NULL,
    trace_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(btrim(tenant_id)) BETWEEN 1 AND 128),
    CHECK (length(btrim(operation_id)) BETWEEN 1 AND 256),
    CHECK (length(btrim(actor_id)) BETWEEN 1 AND 256),
    CHECK (length(btrim(trace_id)) BETWEEN 1 AND 256)
);

CREATE OR REPLACE FUNCTION hallu_reject_deleted_rag_tenant_write()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM rag_tenant_deletion_tombstones
        WHERE tenant_id = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'RAG write rejected for deleted tenant'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    CREATE TRIGGER trg_rag_evidence_reject_deleted_tenant
        BEFORE INSERT OR UPDATE ON rag_evidence_chunks
        FOR EACH ROW
        EXECUTE FUNCTION hallu_reject_deleted_rag_tenant_write();
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;

DO $$
BEGIN
    CREATE TRIGGER trg_rag_ingestion_reject_deleted_tenant
        BEFORE INSERT OR UPDATE ON rag_ingestion_jobs
        FOR EACH ROW
        EXECUTE FUNCTION hallu_reject_deleted_rag_tenant_write();
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;
