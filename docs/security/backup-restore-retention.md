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

## Current Limits

This is policy and CI evidence. It does not execute a database dump, object-storage
snapshot, index snapshot, or restore job on this host. Runtime backup jobs, restore
drill artifacts, and Kubernetes storage integration remain deployment hardening work.
