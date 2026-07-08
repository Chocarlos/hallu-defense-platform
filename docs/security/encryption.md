# Encryption Configuration

This project tracks encryption requirements as policy, not as implied deployment behavior.

The authoritative baseline is `infra/security/encryption-policy.json`. The CI gate
`scripts/ci/check_encryption_config.py` validates that production-facing components require:

- TLS 1.3 or stronger for in-transit traffic.
- No plaintext external interfaces.
- AES-256-class encryption for persisted state.
- Vault-compatible key management.
- Explicit, narrow local-development exemptions.

## Scope

The policy covers active local services and mandatory future services:

- API and console.
- PostgreSQL/pgvector.
- Redis.
- MinIO/S3-compatible artifact storage.
- Prometheus, Grafana, and the OpenTelemetry collector.
- OpenSearch.

## Local Development

Docker Compose is currently a local development profile. It may expose localhost HTTP ports or
container-private plaintext links only where `local_dev_exemptions` records that exception. These
exceptions are not production permission.

Production and shared environments must terminate external traffic through TLS and must use encrypted
volumes, encrypted object storage, and managed encryption keys. A deployment manifest must not be
claimed production-ready unless it satisfies this policy and passes the CI validator.

## Current Limits

This baseline proves configuration intent and CI enforcement. It does not prove that local Docker
services are running with TLS or encrypted volumes on this host. Runtime validation for Kubernetes,
managed databases, object storage, and signed policy bundles remains tracked separately.
