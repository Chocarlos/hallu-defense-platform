# Transactional PostgreSQL Migrations

`scripts/dev/apply_postgres_migrations.py` applies the committed pgvector SQL
files in filename order. The repository currently requires exactly fourteen
versions, from `000_schema_migrations.sql` through
`013_audit_history_integrity.sql`.

## Concurrency and Atomicity

Each invocation opens a single PostgreSQL transaction. Before reading or writing
the ledger it acquires a transaction-scoped advisory lock with
`pg_advisory_xact_lock`. Competing migration runners therefore serialize on the
same database, and PostgreSQL releases the lock automatically on commit or
rollback.

Before acquiring the advisory lock, the runner sets transaction-local
`lock_timeout` to 30 seconds and `statement_timeout` to 14 minutes. This keeps
the complete atomic migration below the deployment Job's 15-minute deadline.
Migration `009` deliberately uses ordinary `DROP INDEX` inside the transaction;
if the table/index lock cannot be acquired within 30 seconds, the whole batch
rolls back without a ledger row and the deployment can retry. It must not be
changed to `DROP INDEX CONCURRENTLY`, which cannot run in this transaction.

The bootstrap ledger update, repository/database reconciliation, every pending
multi-statement migration, and every ledger insert execute inside that single
PostgreSQL transaction. Any SQL or ledger failure rolls back the complete batch;
an earlier migration cannot remain committed without its version record.

The runner creates or upgrades the ledger with a minimal internal SQL invariant,
not by executing `000_schema_migrations.sql` blindly. It then verifies the
recorded checksum for an already-applied `000` before any SQL from that file can
run. A modified bootstrap migration therefore fails closed before execution.

Migration files are sent through psycopg's parameter-less execution path. This
is required for multi-statement SQL. Parameterized advisory-lock and ledger
statements continue to use the parameterized path.

## Integrity Ledger

`schema_migrations` stores the filename and a lowercase SHA-256 checksum of the
UTF-8 migration text. On every run the applier recomputes each checksum:

- a matching recorded checksum is accepted without reapplying SQL;
- checksum drift for an applied migration fails closed;
- a database version missing from the repository fails closed;
- a repository version absent from the database is applied and recorded in the
  same transaction.

Databases created before checksums were introduced can contain legacy NULL checksums.
The first upgraded run backfills those rows from the current committed files without
reapplying SQL. This is a one-time compatibility path because no historical checksum
exists to compare; after backfill, all future file drift is rejected. Migration `013`
runs after that backfill and makes `checksum_sha256` `NOT NULL`, with a validated
lowercase 64-hex-character check. New and upgraded ledgers therefore cannot return to
the compatibility state after the integrity migration commits.

## Required Ordered Set

1. `000_schema_migrations.sql`
2. `001_rag_evidence_chunks.sql`
3. `002_rag_corpus_grants.sql`
4. `003_audit_ledger.sql`
5. `004_approval_queue.sql`
6. `005_eval_reports.sql`
7. `006_ingestion_outbox.sql`
8. `007_ingestion_lease_fencing.sql`
9. `008_schema_migration_checksums.sql`
10. `009_drop_unsafe_ivfflat.sql`
11. `010_add_retrieved_at.sql`
12. `011_rag_lifecycle_outbox.sql`
13. `012_rag_tenant_deletion_fence.sql`
14. `013_audit_history_integrity.sql`

Migration `009` removes the legacy IVFFlat index. The exact vector query is the
correctness baseline: the old index was created before data with a fixed list
count and could lose tenant- or metadata-filtered candidates if a later query
shape activated approximate scanning. Migration `001` remains immutable; the
removal is an explicit forward migration.

Migration `010` adds the required `retrieved_at TIMESTAMPTZ` persistence field,
backfills existing rows from their immutable `created_at` timestamp, and only
then enforces `NOT NULL`. New writes persist the retrieval observation time so
OpenSearch and PostgreSQL can be compared canonically without fabricating a
fresh timestamp at read time.

Migration `011` adds the durable hybrid-RAG lifecycle journal. Its leased state
machine records `pending`, `processing`, `external_deleted`, and `completed`
phases so OpenSearch deletion and parity verification happen before the
PostgreSQL rows plus success audit commit. An interrupted operation remains
retryable without reporting a false success.

Migration `012` adds a durable tenant-deletion tombstone plus database triggers
on evidence and ingestion-job writes. The lifecycle coordinator commits that
tombstone under the same tenant advisory lock as cross-store deletion, and the
hybrid writer checks it after acquiring that lock but before touching
OpenSearch. This prevents queued or in-flight work from recreating deleted
tenant evidence after a successful privacy operation.

Migration `013` adds nullable `audit_runs.completion_path` and transactionally
upgrades legacy completion pairs. A legacy tenant/trace group is backfilled only
when it has exactly one NULL-path run and exactly one unmatched
`verification_completed` event whose path is allowed. The migration then verifies
one-to-one run/event parity for every non-NULL tenant/trace/path completion key. An
unmatched completion without exactly one NULL-path run, duplicate, incompatible path,
or reused legacy trace with ambiguous runs and events fails the migration before
constraints or indexes are installed. A NULL-path run with no completion is retained
as a legitimate historical/import record and is not treated as a backfill candidate.
The pair is never guessed from timestamps. This is important because one trace can
legitimately be reused by v1, v2, and replay in newer data; those writes carry their
path from the start.

After the backfill, a retry of an upgraded legacy request conflicts on both rows and
loads the existing pair instead of inserting a new run beside the old event. New
completion writes are exactly once under a partial unique key of
`(tenant_id, trace_id, completion_path)`. Completion events have the matching partial
unique tenant/trace/path key, while every audit event ID remains unique within its
tenant. `completion_path` remains nullable for explicitly non-completion/import rows,
which are outside the final verification persistence boundary.

Successful `/verification/replay` persistence is a three-record atomic unit: the
replayed run, its `verification_completed` event, and its `verification_replay`
provenance event commit or roll back together. Migration `013` gives the provenance
event its own partial unique tenant/trace/path key, restricted to
`event_type = 'verification_replay'`. A retry therefore reuses the already committed
triple, while duplicate legacy provenance events fail index creation and require
investigation rather than deletion.

The pre-013 replay shape contained one NULL-path replay run and one provenance event,
but no completion event. Migration `013` reconciles that shape only when exactly one
run has `input.replay_of` equal to provenance `source_trace_id` and the run final
decision equals `replay_final_decision`. It sets the replay completion path and inserts
a synthetic `verification_completed` event whose ID is deterministically derived from
the provenance row ID and whose timestamp is the persisted provenance timestamp. A
raw rerun recognizes the resulting triple and performs no write. Final bidirectional
parity requires exactly one run, completion, and provenance event and equality of
source trace and final decisions; every orphan or ambiguity aborts the migration.

The migration also validates the relational/JSONB envelope on both audit tables:
tenant, trace, creation time, and event ID must agree with their payload values. A
`verification_completed` event must be a successful `POST` with status 200, use one
of `/verification/run`, `/v2/verification/run`, or `/verification/replay`, and carry
a valid final decision. Completed runs enforce the same path allowlist and decision
enum. These checks are added `NOT VALID` first and then explicitly validated, so new
writes are fenced immediately while existing rows receive a deliberate validation
pass.

A `verification_replay` provenance event must likewise be a successful `POST` to
exactly `/verification/replay` with status 200. Its metadata must contain a string
`source_trace_id`, valid `source_final_decision` and `replay_final_decision` values,
and a boolean `decision_changed`. The constraint also derives the expected boolean:
`decision_changed` is true exactly when the source and replay final decisions differ.
Special-event tenant IDs must be non-empty and trimmed; request, source, and
`input.replay_of` trace IDs use the exact `^tr_[A-Za-z0-9_-]{8,80}$` contract. Completion
metadata is exactly its final decision, and replay metadata is exactly the four
source/replay decision fields. Invalid or internally inconsistent legacy replay
envelopes fail the validated constraint before the migration can commit.

Export indexes match all four runtime filter shapes for its bounded newest-first
internal export: unscoped, trace-only, tenant-only, and tenant-plus-trace, followed by
`created_at DESC` and the deterministic `id DESC` tiebreaker. The ordered indexes
replace the four legacy prefix-only indexes from migration `003` to avoid duplicate
write and vacuum work.
History-page indexes use tenant, event type, optional trace, `created_at DESC`, and
`event_id DESC`. The migration transactionally drops and recreates each named 013
index and constraint, so executing the raw file again repairs a same-named drifted
definition. The normal migration applier still treats an already-recorded version as
immutable and will not execute it twice; operational schema drift requires an
explicitly reviewed forward migration or controlled raw rerun.

All uniqueness and validation operations fail closed when historical duplicates or
invalid envelopes exist. They never delete or rewrite audit evidence. Operators must
investigate and reconcile such data under their retention/audit process before
retrying deployment.

### Migration 013 rollout and locks

`ALTER TABLE ... VALIDATE CONSTRAINT`, `SET NOT NULL`, and ordinary index creation
scan the existing ledger and acquire PostgreSQL locks. The runner's `lock_timeout`
and `statement_timeout` keep a busy or oversized deployment from hanging; a timeout
rolls back the whole single PostgreSQL transaction, including every dropped/recreated
definition and the version row. On a large production ledger, measure the scans on a
representative copy, check tenant/event, completion-key, and replay-key duplicates,
schedule a maintenance window, and monitor lock waiters before applying 013. Do not
change these indexes to `CREATE INDEX CONCURRENTLY`: concurrent index DDL cannot run
inside the applier's required atomic transaction.

Helm handoff: migration `013` does not require a chart-value change. The chart
owner's current `migration-job.yaml` `activeDeadlineSeconds: 900` remains aligned
with the applier's 14-minute statement timeout. If a representative production
rehearsal cannot finish the validation/index scans within that bound, the Helm owner
(leader D in the six-front workflow) must coordinate any Job deadline adjustment
with a reviewed change to the applier timeouts or a new online forward-migration
strategy; increasing only the Helm deadline would not override PostgreSQL's local
statement timeout.

Adding or removing a file requires an intentional gate, test, documentation, and
deployment update. Applied files must never be edited in place; add a new ordered
migration instead.

## Validation and Execution

Local Compose runs `postgres-migrations` as a one-shot after PostgreSQL is
healthy and the OpenSearch bootstrap succeeds. Both the API and ingestion
worker wait for `service_completed_successfully`, so no application process can
start against an older schema. Production maps the separately scoped
`HALLU_DEFENSE_POSTGRES_MIGRATION_DSN` only into this one-shot as
`HALLU_DEFENSE_POSTGRES_DSN`; API and worker receive neither the migration
variable nor its credential. The production migration one-shot is read-only,
drops all capabilities, enables `no-new-privileges`, and inherits the exact API
image containing this CLI.

Run the offline structural/invariant gate:

```text
make postgres-migrations-check
```

Run the focused behavior tests:

```text
python -m pytest apps/api/tests/test_apply_postgres_migrations.py -q
```

Apply against the configured PostgreSQL database:

```text
HALLU_DEFENSE_POSTGRES_DSN=postgresql://... \
  python scripts/dev/apply_postgres_migrations.py
```

The gate is wired into normal CI, security CI, and `security-check`. It requires
the exact fourteen-file set, immutable `000`, checksum upgrade in `008`, exact-search
guard in `009`, persisted retrieval time in `010`, lifecycle journal in `011`,
tenant deletion fence in `012`, audit completion/envelope/checksum integrity and
exact history indexes in `013`, advisory lock, single
transaction boundary, bounded 30-second lock and 14-minute statement timeouts,
drift/unknown-version rejection, parameter-less
multi-statement execution test, and this documentation.
