CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS rag_evidence_chunks (
    tenant_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    content TEXT NOT NULL,
    authority TEXT NOT NULL CHECK (
        authority IN ('official', 'internal', 'trusted_third_party', 'unknown')
    ),
    staleness_class TEXT NOT NULL CHECK (
        staleness_class IN ('fresh', 'acceptable', 'stale', 'unknown')
    ),
    published_at TIMESTAMPTZ NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    embedding VECTOR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_rag_evidence_chunks_tenant_source
    ON rag_evidence_chunks (tenant_id, source_ref);

CREATE INDEX IF NOT EXISTS idx_rag_evidence_chunks_metadata
    ON rag_evidence_chunks USING gin (metadata);

CREATE INDEX IF NOT EXISTS idx_rag_evidence_chunks_embedding
    ON rag_evidence_chunks USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
