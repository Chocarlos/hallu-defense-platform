# Backup, Restore, And Retention

The authoritative baseline is `infra/security/backup-retention-policy.json`.
The CI gate `scripts/ci/check_backup_retention_config.py` validates the policy
and verifies that Makefile, CI, security workflow, and security docs still wire it in.

Required behavior:

- Persistent components must have backups enabled.
- Backups must be encrypted.
- Backup frequency, RPO, RTO, backup target, and restore drill interval must be explicit.
- Persistent components must run a restore drill at least every 90 days.
- Retention classes must meet the minimum day counts in the policy.
- Deletion must be tenant-scoped and must emit an audit event.

## Covered Components

The baseline covers PostgreSQL/pgvector, the S3-compatible object store (the
stable policy key remains `minio`), OpenSearch, Redis, Prometheus,
Grafana, OpenTelemetry collector buffering, eval reports, and sandbox artifacts.
Redis and the OpenTelemetry collector are marked non-persistent in local development,
but still have explicit retention rules so ephemeral data is not mistaken for durable
evidence.

## Runtime Retention

`apps/api/src/hallu_defense/services/data_lifecycle.py` executes the PostgreSQL
portion of the retention policy. It reads
`infra/security/backup-retention-policy.json`, validates each configured class
against `retention_classes.*.minimum_days`, and refuses policy input that would
delete before the minimum. Retention deletes are limited to literal table names
from committed migrations and use timestamp cutoffs derived from the policy.

Covered PostgreSQL runtime tables:

- `audit_events`
- `audit_runs`
- `approval_execution_grants`
- `approval_records`
- `rag_corpus_grants`
- `rag_evidence_chunks`
- `eval_reports`
- `rag_ingestion_jobs` terminal rows only

Run `scripts/dev/run_retention_execution.py` to execute retention. It is skipped
unless `HALLU_DEFENSE_RETENTION_EXECUTION_ENABLED=true`. Set
`HALLU_DEFENSE_RETENTION_EXECUTION_DRY_RUN=true` to count rows without deleting.

For the production `hybrid` RAG backend, non-dry mutation also requires the
OpenSearch deletion adapter. OpenSearch-only mutation is blocked because it has
no authoritative PostgreSQL parity catalog from which to enumerate every
external evidence ID. Migration
`011_rag_lifecycle_outbox.sql` creates `rag_lifecycle_operations`, a durable
leased journal. Each operation acquires the same tenant advisory lock used by
hybrid ingestion, deletes bounded tenant-scoped evidence-ID batches from
OpenSearch, performs an immediate zero-result parity verification, and only
then commits the matching PostgreSQL deletes, journal completion, and success
audit in one transaction. An external or SQL failure releases the operation for
idempotent retry and emits no success audit. Without the journal/deletion
adapter, hybrid mutations fail closed before deleting PostgreSQL rows.

Migration `012_rag_tenant_deletion_fence.sql` adds a durable tombstone for
successful tenant erasure. The coordinator inserts it in the final SQL
transaction while holding the tenant lifecycle lock; hybrid ingestion checks it
under that same lock before writing OpenSearch, and PostgreSQL triggers reject
new evidence or ingestion jobs. Thus a worker claimed before deletion cannot
recreate tenant data after the success audit commits.

Tenant erasure uses the same CLI:

```text
python scripts/dev/run_retention_execution.py delete-tenant --tenant-id <tenant> --confirm-tenant-id <tenant>
```

It additionally requires `HALLU_DEFENSE_TENANT_DATA_DELETION_ENABLED=true`.
The deletion is parameterized by `tenant_id` across all PostgreSQL-backed
runtime tables and emits a `tenant_data_deletion` audit event after old rows are
removed. Retention execution emits `retention_execution`.

## Backup/Restore Drill

`scripts/dev/backup_restore_drill.py` performs the PostgreSQL backup drill. It
is skipped unless `HALLU_DEFENSE_BACKUP_RESTORE_DRILL_ENABLED=true`.

When enabled, it:

- runs `docker compose exec -T postgres pg_dump` against the source database;
- reads the Fernet key named by
  `HALLU_DEFENSE_BACKUP_ENCRYPTION_SECRET_NAME` through `SecretManager`;
- encrypts the dump with Fernet;
- uploads the encrypted dump through the repository's in-process SigV4 client;
- downloads the object back from the S3-compatible endpoint with a hard byte
  limit and verifies its SHA-256 against the encrypted upload;
- decrypts only the downloaded object and restores it into a scratch database;
- compares row counts and stable row checksums for the PostgreSQL runtime
  tables; and
- writes `var/backup-drills/<timestamp>.json`.

The report contains table counts, row checksums, encrypted-object SHA-256,
object key, and local encrypted artifact path. It records
`restored_from_object_storage=true` only after the downloaded bytes match and
drive `pg_restore`. It never records the Fernet key or raw secret values. The
scratch database must differ from the source database and is dropped after the
parity check.

Local/test runs may use the generic drill's
`HALLU_DEFENSE_BACKUP_DRILL_MINIO_ACCESS_KEY` and
`HALLU_DEFENSE_BACKUP_DRILL_MINIO_SECRET_KEY` fixtures. Production/staging
ignore those plaintext variables, require the Vault backend, and read the
`access_key` and `secret_key` fields from
`HALLU_DEFENSE_BACKUP_DRILL_MINIO_CREDENTIALS_SECRET_NAME` (default
`backup/minio-credentials`). The production endpoint must be HTTPS and match an
exact `HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS` entry.

## Tenant-Scoped S3-Compatible Replica Drill

`scripts/dev/minio_backup_restore_drill.py` exercises the stable MinIO-named policy boundary
from `primary-data-bucket` to `cross-bucket-encrypted-replica`. It is skipped
unless `HALLU_DEFENSE_MINIO_BACKUP_RESTORE_DRILL_ENABLED=true`, and an enabled
run must set `HALLU_DEFENSE_MINIO_BACKUP_DRILL_TENANT_ID`. Source and replica
bucket names must be different. The source enumeration is limited to the exact
`tenants/<tenant-id>/` prefix; every returned object is checked again against
that boundary before any download, so a backend response containing another
tenant fails closed.

For every source object, the drill downloads through `scripts/dev/s3_sigv4.py`
to a private temporary file, computes plaintext size and SHA-256, and writes a
versioned AES-256-GCM
envelope in bounded chunks. The envelope authenticates its magic, format
version, nonce, opaque source reference, size, and plaintext hash as additional
data. The object manifest contains only opaque SHA-256 source references,
replica keys under the synthetic run prefix, sizes, and hashes; it contains no
raw tenant ID, source key, object content, or secret value. The manifest is not
signed and is not an autonomous restore catalog: its integrity and exact parity
are established against the in-memory source snapshot from the same drill run.

Restore reads the manifest and encrypted objects exclusively from the replica
bucket. Every GCM tag, plaintext SHA-256, size, source reference, and manifest
entry must pass before the first synthetic restore object is uploaded. A
corruption therefore fails before restore. The drill then downloads the
synthetic restored objects and checks final hash/size parity. Both the source
restore prefix and the replica run prefix are deleted on success and attempted
again on failure; the original tenant objects are never deleted or overwritten.

The small client uses only the Python standard library and signs each request
with AWS Signature Version 4. Payload hashes are signed, redirects and implicit
write retries are not followed, XML/listing responses are bounded, downloads
use exclusive private files, and object size, total bytes, object count,
manifest size, pages, and duration are bounded. Reports and CLI errors omit
endpoint URLs, credentials, exception text, source keys, and contents.
All multi-page reads and cleanup operations share one monotonic wall-clock
deadline. Before deleting a prefix, the client validates the complete bounded
listing and performs no deletion if even one returned key falls outside the
requested prefix. Production DNS results are checked for non-global addresses
and pinned before connecting, so redirects or DNS rebinding cannot move the
request to loopback, private, link-local, or metadata services.
POSIX temporary downloads are mode 0600. Windows downloads are created with a
protected DACL for only the current user, SYSTEM, and built-in administrators;
failure to establish that DACL fails the download closed.
The encryption key defaults to `backup/encryption-key` and is read through
`SecretManager`; the mutable decoded key buffer is cleared on exit as a
best-effort reduction only. Python strings and cryptographic-library internals
cannot provide a strong zeroization guarantee.

Local/test runs may use the `HALLU_DEFENSE_MINIO_BACKUP_ACCESS_KEY` and
`HALLU_DEFENSE_MINIO_BACKUP_SECRET_KEY` environment variables (the Compose
fixtures are the defaults). The host-side default endpoint is
`http://127.0.0.1:9000`; workloads inside the Compose network continue to use
the stable `http://minio:9000` DNS contract. Production and staging require an
HTTPS S3-compatible endpoint and HTTPS Vault
endpoints, the Vault secret backend, and the `access_key` and `secret_key` fields
from `HALLU_DEFENSE_MINIO_BACKUP_CREDENTIALS_SECRET_NAME` (default
`backup/minio-credentials`). The backup encryption key remains a separate
SecretManager lookup.

Useful optional bounds are:

- `HALLU_DEFENSE_MINIO_BACKUP_MAX_OBJECTS`
- `HALLU_DEFENSE_MINIO_BACKUP_MAX_OBJECT_BYTES`
- `HALLU_DEFENSE_MINIO_BACKUP_MAX_TOTAL_BYTES`
- `HALLU_DEFENSE_MINIO_BACKUP_MAX_LISTING_BYTES`
- `HALLU_DEFENSE_MINIO_BACKUP_MAX_MANIFEST_BYTES`
- `HALLU_DEFENSE_MINIO_BACKUP_CHUNK_BYTES`
- `HALLU_DEFENSE_MINIO_BACKUP_TIMEOUT_SECONDS`

Run the static gate with `make minio-backup-drill-config` and the opt-in live
drill with `make minio-backup-restore-drill` after configuring the S3-compatible store and
SecretManager/Vault. This is a destructive-safe restore drill, not a scheduler,
continuous replication controller, or durable backup lifecycle.
It is not an autonomous restore. Because it deletes its synthetic replica at the end, it
proves the same-run encrypted
replica/restore mechanism but does not implement retention, scheduled copies,
cross-cluster durability, or an autonomous restore.

## Current Limits

Default CI validates the policy, safeguards, and fake-driven tests only. Enabled
retention, tenant deletion, and either backup/restore drill require an operator or
live CI environment with Docker Compose, PostgreSQL, Vault-compatible secrets,
and S3-compatible storage available. OpenSearch snapshots, Prometheus/Grafana backup jobs, and
Kubernetes storage integration remain deployment hardening work.
