-- Audit-history uniqueness and keyset-pagination indexes.
-- The unique index intentionally fails closed when historical duplicates exist;
-- operators must investigate them instead of silently deleting audit evidence.

CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_tenant_event_id
    ON audit_events (tenant_id, event_id);

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_type_created_event
    ON audit_events (
        tenant_id,
        (payload ->> 'event_type'),
        created_at DESC,
        event_id DESC
    );

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_type_trace_created_event
    ON audit_events (
        tenant_id,
        (payload ->> 'event_type'),
        trace_id,
        created_at DESC,
        event_id DESC
    );
