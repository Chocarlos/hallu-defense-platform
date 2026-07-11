# ADR 0007: Production Deployment

## Status

Accepted for the Batch 7 deployment scaffold.

## Context

The platform now has real production-like requirements for authentication,
durable storage, Vault-compatible secrets, metrics scrape authentication,
containerized sandbox execution, eval report persistence, durable ingestion,
and Kubernetes packaging. Production packaging must name every backend whose
local default is intentionally rejected in production.

## Decision

Use a `docker-compose.prod.yml` overlay over the base Compose file for the first
production profile. The overlay sets the API and ingestion worker to production
auth, OIDC JWT claims, Vault secrets, PostgreSQL-backed audit/approvals/corpus
grants/eval reports, a non-mock provider adapter, pgvector retrieval, OTLP,
HTTPS-only CORS, Docker sandbox execution, and Prometheus `credentials_file`
scrape auth.

Use Compose `!override` for runtime environments and mounts so local settings do
not leak through merge semantics. Remove all local data, identity, secrets, and
observability services from the merged production model with `!reset null`.
Production endpoints and models are required interpolation values rather than
syntactically valid placeholders. The production merge therefore contains only
API, console, and ingestion-worker and connects to externally operated
dependencies.

Give the ingestion worker a separate environment without the Vault token,
provider configuration, or API-only mounts. Some non-secret API-oriented keys
remain temporarily because all processes call the same `Settings` loader; a
role-specific settings contract is a follow-up rather than a reason to grant
the worker additional credentials.

Mounting `/var/run/docker.sock` is documented as root-equivalent host access. It
is accepted only for the Compose profile scaffold so the API can reach the
Docker sandbox backend. Kubernetes deployments should prefer a dedicated sandbox
worker or a constrained runtime integration.

Add a Helm chart under `infra/k8s/helm/hallu-defense` with API, console, worker
template, migration Job, secret templates, pgvector/OpenSearch kind defaults,
non-root security contexts, probes, resource limits, and Prometheus scrape
annotations. The worker is enabled by default now that the Batch 6 runtime
exists. The API image carries the migration applier and SQL files referenced by
the migration Job.

## Consequences

- The production overlay is statically gateable without requiring Docker on
  every local machine.
- The Helm chart can be templated and checked before live kind validation is
  enabled.
- The Docker socket tradeoff is visible instead of hidden in runtime config.
- Static gates reject production `mock`/memory backend regressions and missing
  migration assets before a deployment is attempted.
- Runtime configuration rejects plaintext Vault/provider transports and OIDC
  discovery documents that downgrade their discovered JWKS endpoint to HTTP.
- The local Compose infrastructure remains available through the base file but
  cannot be inherited or started by the merged production profile.
