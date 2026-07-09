CREATE TABLE IF NOT EXISTS eval_reports (
    id BIGSERIAL PRIMARY KEY,
    report_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    suite TEXT NOT NULL,
    run_id TEXT NOT NULL,
    source TEXT NOT NULL,
    metrics JSONB NOT NULL,
    payload JSONB NOT NULL,
    published_by TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_eval_reports_tenant_published_at
    ON eval_reports (tenant_id, published_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_eval_reports_tenant_suite_published_at
    ON eval_reports (tenant_id, suite, published_at DESC, id DESC);
