-- Add immutable-content checksums without rewriting the already-applied
-- 000_schema_migrations.sql history. The runtime applier bootstraps this column
-- internally before reading a legacy ledger, then records this migration like
-- every other ordered version.
ALTER TABLE schema_migrations
    ADD COLUMN IF NOT EXISTS checksum_sha256 text;
