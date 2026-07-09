# ADR 0007: Production Deployment

## Status

Accepted for the Batch 7 deployment scaffold.

## Context

The platform now has real production-like requirements for authentication,
durable storage, Vault-compatible secrets, metrics scrape authentication,
containerized sandbox execution, and Kubernetes packaging. The deployment layer
must fail closed without pretending that unresolved Batch 5 eval report APIs or
Batch 6 ingestion worker runtime are complete.

## Decision

Use a `docker-compose.prod.yml` overlay over the base Compose file for the first
production profile. The overlay sets production auth, OIDC JWT claims, Vault
secrets, PostgreSQL-backed audit/approvals/corpus grants, pgvector retrieval,
OTLP, HTTPS-only CORS, Docker sandbox execution, and Prometheus
`credentials_file` scrape auth.

Mounting `/var/run/docker.sock` is documented as root-equivalent host access. It
is accepted only for the Compose profile scaffold so the API can reach the
Docker sandbox backend. Kubernetes deployments should prefer a dedicated sandbox
worker or a constrained runtime integration.

Add a Helm chart under `infra/k8s/helm/hallu-defense` with API, console, worker
template, migration Job, secret templates, pgvector/OpenSearch kind defaults,
non-root security contexts, probes, resource limits, and Prometheus scrape
annotations. The worker template remains disabled by default until the Batch 6
runtime exists.

## Consequences

- The production overlay is statically gateable without requiring Docker on
  every local machine.
- The Helm chart can be templated and checked before live kind validation is
  enabled.
- The Docker socket tradeoff is visible instead of hidden in runtime config.
- Eval report runtime and ingestion worker dependencies remain explicit rather
  than implemented in this slice.
