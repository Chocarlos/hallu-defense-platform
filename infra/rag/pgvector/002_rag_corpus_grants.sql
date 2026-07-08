CREATE TABLE IF NOT EXISTS rag_corpus_grants (
    sequence_id BIGINT GENERATED ALWAYS AS IDENTITY,
    tenant_id TEXT NOT NULL,
    corpus_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    reader_roles TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    writer_roles TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    disabled_by TEXT NULL,
    disabled_at TIMESTAMPTZ NULL,
    payload JSONB NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, corpus_id, version),
    UNIQUE (sequence_id),
    CHECK ((disabled_by IS NULL) = (disabled_at IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_rag_corpus_grants_tenant_corpus_latest
    ON rag_corpus_grants (tenant_id, corpus_id, version DESC);

CREATE INDEX IF NOT EXISTS idx_rag_corpus_grants_tenant_updated_at
    ON rag_corpus_grants (tenant_id, updated_at);

CREATE INDEX IF NOT EXISTS idx_rag_corpus_grants_tenant_updated_by
    ON rag_corpus_grants (tenant_id, updated_by);
