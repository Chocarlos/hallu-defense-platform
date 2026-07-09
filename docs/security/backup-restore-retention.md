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

The baseline covers PostgreSQL/pgvector, MinIO, OpenSearch, Redis, Prometheus,
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
- uploads the encrypted dump with a one-shot `minio/mc` container to MinIO;
- restores the decrypted dump into a scratch database;
- compares row counts and stable row checksums for the PostgreSQL runtime
  tables; and
- writes `var/backup-drills/<timestamp>.json`.

The report contains table counts, checksums, object key, and local encrypted
artifact path. It never records the Fernet key or raw secret values. The scratch
database must differ from the source database and is dropped after the parity
check.

## Current Limits

Default CI validates the policy, safeguards, and fake-driven tests only. Enabled
retention, tenant deletion, and the backup/restore drill require an operator or
live CI environment with Docker Compose, PostgreSQL, Vault-compatible secrets,
and MinIO available. OpenSearch snapshots, Prometheus/Grafana backup jobs, and
Kubernetes storage integration remain deployment hardening work.
