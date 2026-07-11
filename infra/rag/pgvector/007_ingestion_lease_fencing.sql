-- Fence terminal ingestion transitions with a token that changes on every claim.
-- Kept separate from 006 so databases that already recorded the outbox migration
-- receive the new column through the idempotent migration applier.

ALTER TABLE rag_ingestion_jobs
    ADD COLUMN IF NOT EXISTS lease_token text;
