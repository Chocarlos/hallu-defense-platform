-- Migration ledger for the idempotent applier.
--
-- This file MUST NOT depend on any extension. Under the docker initdb mount the
-- *.sql files run in alphabetical order, so 000_ executes before 001_ (which
-- creates the `vector` extension). Keeping this bootstrap extension-free lets it
-- run first on an empty volume and lets the applier run it unconditionally.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
