# Audit Ledger

The API audit ledger supports three backends:

- `memory`: local/test-only process memory for fast development.
- `jsonl`: append-only JSON Lines storage for verification runs and audit events.
- `postgres` (alias `postgresql`): append-only PostgreSQL storage for verification
  runs and audit events, sharing the pooled `SqlConnectionProvider` seam.

Production and staging must not use `memory`; `create_audit_ledger()` rejects that
configuration at startup. Use the `jsonl` backend:

```text
HALLU_DEFENSE_AUDIT_LEDGER_BACKEND=jsonl
HALLU_DEFENSE_AUDIT_LEDGER_PATH=var/audit/audit-ledger.jsonl
```

or the `postgres` backend:

```text
HALLU_DEFENSE_AUDIT_LEDGER_BACKEND=postgres
HALLU_DEFENSE_POSTGRES_DSN=postgresql://user:pass@host:5432/hallu_defense
```

## Postgres backend

The `postgres`/`postgresql` backend writes each redacted verification run and audit
event as a JSONB payload into the migration-managed `audit_runs` and `audit_events`
tables. It is **fail-closed**: `create_audit_ledger(settings, sql_provider=...)`
raises `AuditLedgerConfigurationError` when the backend is selected but no
`SqlConnectionProvider` is injected. The provider is wired by the application
dependency layer from `HALLU_DEFENSE_POSTGRES_DSN`.

Writes use parameterized inserts (`payload` bound as `%s::jsonb`). Reads are indexed
on `(tenant_id, created_at)` and `(tenant_id, trace_id)`; the WHERE clause is built
only from the requested tenant/trace filters and results are bounded by the export
cap via `ORDER BY created_at DESC LIMIT %s`. The most recent records are then
returned in chronological (ascending) order so postgres exports match the
memory/jsonl backends.

## Minimization

All backends write a redacted copy of verification runs and audit events.
Sensitive-looking keys and text containing secret-like terms are replaced with
`[REDACTED]` before storage, so raw secrets never reach the JSONL file or the
PostgreSQL rows. The API still keeps tenant and trace identifiers so exports remain
useful for investigation without turning audit into raw payload logs.

## Export bound

`export()` and `export_events()` return at most `audit_export_max_records` (default
`1000`) of the **most recent** records that match the tenant/trace filter, for every
backend. memory/jsonl apply the bound as a slice over the in-memory records;
postgres applies it as the SQL `LIMIT`. Older records beyond the bound are dropped
from a single export response (they remain persisted in the ledger).

## Validation

`scripts/ci/check_audit_ledger_config.py` validates the configuration surface and CI
wiring. `apps/api/tests/test_audit_ledger.py` verifies append-only persistence,
reload, tenant filtering, redaction, production startup rejection for `memory`,
fail-closed handling for corrupt records, the postgres INSERT/SELECT shape with
redaction parity, the fail-closed postgres factory, and the export bound.
