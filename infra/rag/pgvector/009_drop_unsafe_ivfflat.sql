-- The production query is intentionally exact. The legacy IVFFlat index was
-- created before data with fixed lists and could silently reduce filtered
-- recall if a future query shape made the planner use it.
DROP INDEX IF EXISTS idx_rag_evidence_chunks_embedding;
