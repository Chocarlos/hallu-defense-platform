ALTER TABLE rag_evidence_chunks
    ADD COLUMN IF NOT EXISTS retrieved_at TIMESTAMPTZ;

UPDATE rag_evidence_chunks
SET retrieved_at = created_at
WHERE retrieved_at IS NULL;

ALTER TABLE rag_evidence_chunks
    ALTER COLUMN retrieved_at SET NOT NULL;
