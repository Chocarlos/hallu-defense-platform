# Audit Ledger

The API audit ledger supports three backends:

- `memory`: local/test-only process memory for fast development.
- `jsonl`: append-only JSON Lines storage for local development and compatibility
  tests. Completed runs use one compound record, so a valid record never exposes
  only one half of the completion pair or replay triple.
- `postgres` (alias `postgresql`): append-only PostgreSQL storage for verification
  runs and audit events, sharing the pooled `SqlConnectionProvider` seam.

Production and staging require `postgres`. `create_audit_ledger()` rejects both
`memory` and `jsonl` in production-like environments and fails closed when the
PostgreSQL backend has no injected `SqlConnectionProvider`.

Local development may use:

```text
HALLU_DEFENSE_AUDIT_LEDGER_BACKEND=jsonl
HALLU_DEFENSE_AUDIT_LEDGER_PATH=var/audit/audit-ledger.jsonl
```

Production and staging use:

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
on tenant, trace, event type, completion path, and newest-first keyset fields. Every
row returned by PostgreSQL is revalidated against the requested tenant and trace,
the relational envelope (`tenant_id`, `trace_id`, `completion_path`, `event_id`,
`created_at`), the JSON payload, unique database/event IDs, the requested limit,
and database ordering. A coherent snapshot also compares every visible
run/completion/provenance unit for final-decision and replay-source parity. A row
outside the request scope fails the complete read instead of being filtered in
process.

## Atomic verification completion

The only supported event boundary for a final `VerificationRun` is
`AuditLedger.append_completed_run()`. It persists the redacted run and its
`verification_completed` event atomically and exactly once for a
tenant/trace/path. Direct `append_event(event_type="verification_completed")` is
rejected so callers cannot create an orphan history event.

Replay uses the specialized `AuditLedger.append_replayed_run()` boundary. It
commits the replayed run, `verification_completed`, and the public
`verification_replay` provenance event as one three-record unit. Direct writes of
either event type are rejected. Provenance keeps the source/replay decisions,
source trace, and derived `decision_changed` flag without treating validated trace
identifiers as secrets merely because they contain words such as `secret` or
`token`. Replay source lookup excludes every non-null `replay_of` marker before
reading at most two exact candidates, independently of the public export cap.
Cardinality zero preserves the tenant-safe `404`, one candidate replays, and more
than one candidate fails closed with a stable `409` before orchestration or provider
work; the lookup never silently chooses one duplicate.

PostgreSQL performs both or all three conflict-aware inserts inside one transaction. Migration
`013_audit_history_integrity.sql` makes the tenant/trace/path identity unique for
completed runs and completion events. A new write must insert both rows; an
idempotent retry must find the complete existing unit and prove every payload and
envelope matches. Any mixed insert result, duplicate state, or conflicting retry
raises an integrity error and rolls the whole transaction back. Concurrent retries
converge on one pair or replay triple. Retry comparison ignores only the run
timestamp and evidence retrieval-observation timestamp; decisions, content,
authority, staleness, policy output, and provenance must still match.

The route layer validates the orchestrator's tenant/trace identity and owns this
boundary after response construction. The verification
orchestrator computes runs but never persists them, preventing the former double
write. Memory applies the same unit/deduplication invariant under one lock. JSONL
writes the pair or triple as one compound record and adopts the legacy compound-plus-
provenance format on reload without moving a synthesized completion past newer
events. Actual JSONL `OSError` failures are wrapped as storage errors so verification
routes return the same generic `503`; PostgreSQL remains the production atomicity
guarantee.

Memory and JSONL also deeply own every model graph. Runs, completion/provenance
events, and generic event metadata are cloned on ingress, kept as storage-owned
objects, and cloned again for every append, retry, export, snapshot, pagination,
and replay-source return. Mutating a caller object or any prior nested return cannot
alter a later snapshot or a JSONL reload.

## Verification history

`POST /verification/runs/list` is derived only from validated
`verification_completed` events. It uses bounded newest-first keyset pagination and
revalidates tenant, optional trace filter, event type, `POST` method, allowlisted
path, status `200`, successful outcome, timezone-aware timestamp, event ID, and
final decision. Malformed cursors return `400`; persisted integrity and storage
failures return a generic `503` without exposing database data.

## Minimization

Front A keeps deterministic typed pre-storage seams in
`_redact_verification_run()` and `_redact_audit_event()` and proves that the
persisted copies never replace or mutate successful public responses. Its current
compatibility redactor replaces sensitive-looking keys, recognized secret values,
and supported signed-query patterns with `[REDACTED]` before any backend write.
Every persisted run and event, including replay provenance, crosses one of those
two seams. The helpers preserve only validated structural `replay_of` and
`source_trace_id` identities. The API keeps validated tenant and trace identifiers
so exports remain useful for investigation.

Full bounded PII and signed-URL inspection across every persisted run/event field
is a mandatory root-integration dependency on Front B; this branch does not copy
that central redactor from another worktree. Integration must preserve the typed
pre-storage boundary, tenant/trace/event envelope parity, deterministic bounded
processing, and public-response fidelity.

Idempotent conflict comparison currently operates on that minimized persisted
projection. Distinct sensitive originals can therefore collide if the compatibility
redactor maps both to the same value. Root integration must add a keyed, non-exported
pre-redaction request commitment if those originals must remain distinguishable;
this branch intentionally does not persist an unkeyed raw-input digest.

## Export bound

`POST /audit/export` consumes one `AuditLedger.export_snapshot()` unit. PostgreSQL
starts `REPEATABLE READ, READ ONLY` before the first `SELECT` and executes both
bounded reads through the same transaction-bound provider, so a commit between
the run and event queries is invisible to both halves. memory/jsonl copy runs and
events while holding one lock. `include_events=false` skips the event read/copy.
The single-collection compatibility helpers `export()` and `export_events()` do
not promise cross-collection snapshot coherence.

A snapshot storage or integrity failure aborts the entire export with a documented
generic `503` (`Audit history is unavailable.`). Backend exception text is never
included and no interleaved or partial response is returned.

Each included collection returns at most `audit_export_max_records` (default
`1000`) of the **most recent** records matching the tenant/trace filter. PostgreSQL
uses a bounded `cap + 1` SQL lookahead to distinguish an exact-cap result from real
truncation, then returns only the cap; memory/jsonl cap each copied collection.
When neither collection is truncated, path and replay-triple key sets must match
exactly. A truly truncated response still validates every visible matching unit
without treating an intentionally omitted older counterpart as corruption. Older
records remain persisted.

## Validation

`scripts/ci/check_audit_ledger_config.py` validates the configuration surface and CI
wiring. `apps/api/tests/test_audit_ledger.py` verifies append-only compatibility,
redaction, production rejection for memory/JSONL, atomic rollback, sequential and
concurrent pair/triple idempotency, PostgreSQL filter/envelope validation, the fail-closed
factory, duplicate-ID/cardinality rejection, and export bounds. A deterministic
interleaving regression commits a new completion pair between the two former reads
and proves that PostgreSQL and local exports expose neither half of that concurrent
commit in the snapshot already in progress. Additional regressions cover visible
run/completion/provenance parity, pre-cap replay lookup, real JSONL write failure,
replay seam traversal, and legacy replay cap ordering.
