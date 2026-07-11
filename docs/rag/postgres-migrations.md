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
exists to compare; after backfill, all future file drift is rejected.

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

Migration `013` makes audit event IDs unique within a tenant and adds the exact
tenant/event-type/trace/time indexes used by newest-first keyset history pages.
The unique index intentionally fails if historical duplicates exist; operators
must investigate them before deployment rather than deleting audit evidence.

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
tenant deletion fence in `012`, audit-history integrity indexes in `013`, advisory lock, single
transaction boundary, bounded 30-second lock and 14-minute statement timeouts,
drift/unknown-version rejection, parameter-less
multi-statement execution test, and this documentation.
