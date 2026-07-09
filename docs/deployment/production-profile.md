# Production Profile

`docker-compose.prod.yml` is a fail-closed production overlay, not a Compose
`profiles:` mode. Validate the merged shape with:

```text
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
```

`scripts/ci/check_prod_profile_config.py` runs static assertions every time and
runs that Docker Compose command when Docker is available. It skips when Docker
is unavailable, which keeps default CI and Windows shells deterministic.
The expected behavior is documented as: skips when Docker is unavailable.

The overlay switches the API to:

- `HALLU_DEFENSE_ENV=production`
- `HALLU_DEFENSE_AUTH_REQUIRED=true`
- `HALLU_DEFENSE_AUTH_CLAIMS_MODE=oidc_jwt`
- `HALLU_DEFENSE_SECRETS_BACKEND=vault`
- PostgreSQL-backed audit ledger, approval queue, corpus grants, and pgvector
  RAG index backends.
- `HALLU_DEFENSE_INGESTION_MODE=async` with the Batch 6 ingestion worker
  runtime and status endpoint available through the worker service.
- OTLP trace export to `otel-collector`.
- HTTPS-only CORS placeholder `https://console.example.invalid`.

The OIDC issuer placeholder is
`https://auth.example.invalid/realms/hallu-defense`. Export a real Keycloak
public JWKS before starting the profile:

```text
python scripts/dev/export_keycloak_jwks.py --output var/keycloak/jwks.json
```

`var/keycloak/jwks.json` is gitignored and mounted read-only at
`/run/hallu-defense/keycloak-jwks.json`.

## Secrets

The production profile requires runtime secrets through environment variables or
gitignored files:

- `HALLU_DEFENSE_RUNTIME_VAULT_TOKEN`
- `HALLU_DEFENSE_POSTGRES_DSN`
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`
- `GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD`
- `var/prometheus/api-metrics.jwt`

Do not put production secret values into `.env.example` or committed Compose
files. Local Vault development still uses the existing local-only helper:

```text
python scripts/dev/bootstrap_local_vault.py
python scripts/dev/live_vault_secrets_smoke.py
```

## Sandbox Socket Mount

The profile sets `HALLU_DEFENSE_SANDBOX_BACKEND=docker` and mounts
`/var/run/docker.sock` into the API container. This is root-equivalent Docker
socket access on the host. It is included only so the Compose production profile
can exercise the same Docker sandbox backend as the runtime; a hardened
deployment should replace it with a constrained remote Docker API, a dedicated
sandbox worker, or Kubernetes-native isolation.
This root-equivalent Docker socket tradeoff must be removed or isolated before
managed Kubernetes production use.

## Prometheus Credentials

Production Prometheus uses `infra/prometheus/prometheus.prod.yml`, which reads
the API metrics bearer token via `authorization.credentials_file` at
`/run/secrets/hallu_defense_metrics_bearer_token`. The Compose overlay mounts
`var/prometheus/api-metrics.jwt` to that path. Inline Prometheus credentials and
default service credentials are rejected by the static gate.

## Live E2E Scaffold

`scripts/dev/live_prod_profile_e2e.py` is disabled by default. When
`HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_ENABLED=true`, it expects a deployed API
URL and a real OIDC bearer token, then checks auth, verification, approval,
grant consumption, sandbox, corpus grants, audit export, and metrics. Batch 5
eval report APIs and the Batch 6 ingestion worker runtime are part of the
expected production profile surface.
The current roadmap dependency marker is: Batch 5 eval report APIs.
