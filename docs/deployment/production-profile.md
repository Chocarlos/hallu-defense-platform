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

The overlay uses the standard Compose `!override` and `!reset` merge tags. API,
console, ingestion-worker, and the one-shot `opensearch-bootstrap` are the only
services in the merged production model. Postgres, Redis, MinIO, OpenSearch,
Prometheus, Grafana, the OTel
collector, local Keycloak, and Vault are removed with Compose `!reset null`;
production must connect to separately operated services instead of inheriting
their local plaintext ports, development modes, or default credentials. The
bootstrap resets its local OpenSearch dependency. API and worker depend only on
that one-shot with `condition: service_completed_successfully`; a failed or
incompatible schema therefore prevents both long-running processes from
starting. Docker Compose 2.24.4 or newer is required for these merge tags; older
versions fail during configuration rather than silently weakening the overlay.

The API environment is replaced rather than merged with the local environment.
It sets:

- `HALLU_DEFENSE_ENV=production`
- `HALLU_DEFENSE_AUTH_REQUIRED=true`
- `HALLU_DEFENSE_AUTH_CLAIMS_MODE=oidc_jwt`
- `HALLU_DEFENSE_SECRETS_BACKEND=vault`
- PostgreSQL-backed audit ledger, approval queue, corpus grants, and eval
  reports, plus `HALLU_DEFENSE_RAG_INDEX_BACKEND=hybrid`. Every RAG write must
  succeed in both pgvector and OpenSearch; searches reconcile the two durable
  indexes instead of silently degrading to a process-local backend. In particular,
  `HALLU_DEFENSE_EVAL_REPORTS_BACKEND=postgres` is explicit so the API cannot
  fall back to the production-forbidden in-memory default.
- `HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME=approvals/tool-call-commitment-key`.
  Operators must provision that logical Vault secret with at least 32 bytes of
  random key material before startup. The raw key is never accepted through an
  environment variable; production and staging reject an absent, unreadable,
  or undersized SecretManager value instead of falling back to unkeyed SHA-256.
- `HALLU_DEFENSE_PROVIDER_BACKEND=openai-compatible` with a required HTTPS
  gateway, model, and Vault secret name. Production never inherits the `mock`
  default.
- `HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND=redis`, with the Redis URL
  resolved only from Vault secret
  `HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME=quotas/tool-validation/redis-url`
  and TLS verified through
  `HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_CA_PATH=/run/hallu-defense/redis/ca.crt`.
- `HALLU_DEFENSE_OPA_ENABLED=true`,
  `HALLU_DEFENSE_OPA_PATH=/usr/local/bin/opa`, and
  `HALLU_DEFENSE_OPA_POLICY_DIR=/app/infra/opa/policies`. The API image copies
  only the runtime policy directory into the final image. Its OPA 1.17.0 static
  binary is reproducibly built from the pinned official v1.17.0 source commit
  with the pinned Go 1.26.4 builder and patched `x/crypto`, `x/net`, `x/sys`, and
  `oras-go` module versions. Every base stage is pinned by digest; the build
  verifies module checksums and provenance, then runs `opa version` and
  `opa check --strict`.
  Missing executables, timeouts, malformed or oversized output, and non-zero
  policy evaluation exits fail closed without returning OPA stderr or input.
  On POSIX, startup additionally rejects a symlinked, non-root-owned, or writable
  OPA executable or policy tree, including write access held by the API runtime
  identity. Windows has no portable POSIX ownership/mode equivalent; production
  immutability evidence there is therefore limited to the read-only, non-root
  container controls validated for this image rather than inferred from NTFS
  ACLs.
- `HALLU_DEFENSE_INGESTION_MODE=async` with the Batch 6 ingestion worker
  runtime and status endpoint available through the worker service.
- `HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES=1048576`, enforced inside the ASGI
  application before routing or authentication.
- `HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS=15`, with a supported maximum of
  60 seconds for receiving the complete bounded request body.
- `HALLU_DEFENSE_SANDBOX_BACKEND=kubernetes`, a sandbox runner image pinned by
  `sha256`, a single tenant-bound namespace/PVC, and an existing default-deny
  NetworkPolicy. Runtime validation rejects both `host` and `docker` in every
  production/staging profile; those backends are local/CI-only.

- OTLP trace export to a required external endpoint.
- HTTPS-only CORS configured explicitly by the deployer.

The Console environment is also replaced rather than merged. It uses only
server-runtime `HALLU_DEFENSE_CONSOLE_*` values, requires OIDC, canonical HTTPS
Console/API origins and issuer, and cannot inherit the base Compose unsigned
fixture. `NEXT_PUBLIC_*` configuration is forbidden. See
`docs/security/console-oidc.md` for the complete contract and session boundary.

The API, ingestion worker, bootstrap job, and console also set `read_only: true`, drop `ALL` Linux
capabilities, enable `no-new-privileges:true`, and mount `/tmp` as a
`rw,noexec,nosuid,nodev` tmpfs. Application source, scripts, the OPA binary, and
`/app/infra/opa/policies` remain root-owned and non-writable by UID 10001. The
API mounts the tenant-bound `/workspace` read-only; the worker has no persistent
writable mount. Only the authorized sandbox Job receives the scoped writable
workspace view and produces its report. This prevents a compromised verification
plane from changing repository evidence before a check runs.

The ingestion worker has a separate minimal environment. It receives the
PostgreSQL DSN file and the persistent audit/corpus/RAG/ingestion settings it uses.
Because the hybrid writer authenticates to OpenSearch, it also receives the
short-lived token mounted through `HALLU_DEFENSE_VAULT_TOKEN_FILE`, the logical
`HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME`, and read-only Vault and
OpenSearch CA mounts. It does not receive provider settings, OPA settings,
Kubernetes sandbox credentials/settings, Redis credentials, OTLP endpoint, or
OIDC/JWKS, CORS, or workspace configuration. It receives only the logical
`HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME`; the authenticated worker
metrics server binds port 9090, rejects missing/wrong Bearer tokens, emits
`Cache-Control: no-store`, and resolves rotation through Vault without a raw
token environment variable. Its pinned worker
role validates PostgreSQL persistence plus Vault/OpenSearch transport and
requires the Vault token and CA before constructing the worker; API auth,
provider, OPA, rate-limit, OTLP, and sandbox validators do not run.

## Required Deployment Values

Compose required interpolation (`${NAME:?message}`) makes the following values
mandatory before config or startup; no `.example.invalid` endpoint is a valid
production default:

- for the API only, `HALLU_DEFENSE_OIDC_ISSUER`,
  `HALLU_DEFENSE_OIDC_AUDIENCE`, and
  `HALLU_DEFENSE_OIDC_JWKS_FILE`;
- `HALLU_DEFENSE_CORS_ALLOW_ORIGINS` plus the Console's
  `HALLU_DEFENSE_CONSOLE_PUBLIC_ORIGIN`, `HALLU_DEFENSE_CONSOLE_API_ORIGIN`,
  `HALLU_DEFENSE_CONSOLE_OIDC_ISSUER`,
  `HALLU_DEFENSE_CONSOLE_OIDC_CLIENT_ID`, and
  `HALLU_DEFENSE_CONSOLE_OIDC_API_AUDIENCE`;
- `HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS`;
- `HALLU_DEFENSE_VAULT_ADDR`, the host CA file, and
  `HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE`, bound inside the containers to
  `HALLU_DEFENSE_VAULT_CA_CERT_PATH=/run/hallu-defense/vault/ca.crt`;
- `HALLU_DEFENSE_POSTGRES_DSN_FILE`, an absolute host path containing the
  runtime DSN, and `HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH`, bound read-only
  to `/run/hallu-defense/postgres/ca.crt`. Both runtime and migration DSNs must
  set `sslmode=verify-full` and
  `sslrootcert=/run/hallu-defense/postgres/ca.crt`, plus
  `ssl_min_protocol_version=TLSv1.3` and `gssencmode=disable`; startup rejects weaker TLS,
  a different root path, or an unavailable CA without printing the DSN;
- `HALLU_DEFENSE_OPENSEARCH_ENDPOINT`, which must be HTTPS and whose canonical
  origin must appear in `HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS`;
- `HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME`, a logical Vault path
  such as `rag/opensearch/authorization`, never an Authorization header value;
- the host OpenSearch CA bound read-only to
  `HALLU_DEFENSE_OPENSEARCH_CA_CERT_PATH=/run/hallu-defense/opensearch/ca.crt`
  for both API and worker;
- `HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE`, containing a separately scoped,
  short-lived token that may read only the OpenSearch authorization secret used
  by the one-shot;
- the host Redis TLS CA bound read-only to
  `/run/hallu-defense/redis/ca.crt`;
- `HALLU_DEFENSE_PROVIDER_MODEL`,
  `HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL`, and
  `HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME`;
- `HALLU_DEFENSE_OTEL_ENDPOINT` and
  `HALLU_DEFENSE_ALLOWED_WORKSPACE_HOST`;
- `HALLU_DEFENSE_SANDBOX_KUBERNETES_IMAGE`, namespace, PVC, NetworkPolicy, and
  tenant ID, plus `KUBERNETES_SERVICE_HOST` and
  `KUBERNETES_SERVICE_PORT_HTTPS`;
- the dedicated ServiceAccount token and Kubernetes CA host files mounted
  read-only at `/var/run/secrets/kubernetes.io/serviceaccount/token` and
  `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.

Production and staging runtime validation rejects plaintext Vault and provider
URLs. OIDC remote configuration also rejects a plaintext `jwks_uri` returned by
an otherwise HTTPS discovery document.

### Outbound HTTPS origins

`HALLU_DEFENSE_OUTBOUND_HTTPS_ALLOWED_ORIGINS` is a required, non-empty,
comma-separated list in production and staging. Each entry is one exact HTTPS
origin only: scheme, IDNA-normalized host, and effective port. Credentials,
paths, queries, fragments, wildcards, duplicate canonical origins, and trailing
DNS dots are rejected. An omitted `:443` and an explicit `:443` are the same
origin.

List every active Vault, provider, remote OIDC issuer/discovery/JWKS,
OpenSearch, and OTLP HTTP origin. Private IP literals are permitted only when
the exact origin is listed and its purpose and owner are recorded in the
deployment change record. Loopback, link-local, unspecified, and multicast IP
literals are always rejected in production and staging.

All stdlib HTTP transports and the OTLP HTTP session fail closed: redirects are
rejected before a second request is sent, including same-origin redirects. No
`Authorization`, `X-Vault-Token`, Kubernetes ServiceAccount bearer token, or
OTLP header is forwarded to a redirect target. Local and test environments may
leave the allowlist empty so existing localhost HTTP workflows remain usable;
redirects are rejected there as well.

### Inbound request size boundary

The API caps every HTTP request body at 1 MiB by default through
`HALLU_DEFENSE_MAX_REQUEST_BODY_BYTES=1048576`. The configured value must be
between 1 byte and 16 MiB. A malformed or conflicting `Content-Length`, an
ambiguous `Transfer-Encoding`/`Content-Length` combination, or a noncanonical
transfer encoding returns 400. A declared or streamed body that crosses the
limit returns 413. The total receive deadline defaults to
`HALLU_DEFENSE_REQUEST_BODY_TIMEOUT_SECONDS=15` and returns 408 when exceeded;
the supported range is 1 to 60 seconds. The limiter caps framing at 4,096 ASGI
body messages, collapses accepted chunks into one bounded replay, and requires
declared and actual lengths to match. HTTP/2 rejects transfer encoding, while
HTTP/1.1 permits only canonical chunked framing. Rejections do not drain an
unbounded body, and HTTP/1.x rejections close the connection.

Ingresses and reverse proxies must enforce a body limit no larger than the
application limit. Large corpora must use bounded ingestion chunks or upload
batches rather than raising this limit without a capacity review. The public
Pydantic v1/v2 payload contracts remain unchanged; this is a transport safety
boundary applied before parsing and authentication. Pre-authentication audit
events use the reserved unauthenticated tenant instead of trusting a caller's
`x-tenant-id`. Audit, metrics, and telemetry use the fixed `__unmatched__`
route label for pre-routing rejections; raw attacker-controlled paths are not
exported, preventing secret leakage and unbounded cardinality.

### OpenSearch schema bootstrap

Production startup includes an `opensearch-bootstrap` one-shot using the exact
API image and the packaged command
`python /app/scripts/dev/bootstrap_opensearch_template.py`. Its pinned
`HALLU_DEFENSE_RUNTIME_ROLE=opensearch-bootstrap` validates only OpenSearch,
Vault, CA, timeout, index, and outbound-policy settings. It receives no
PostgreSQL DSN, JWKS, Redis, provider, OTLP, OPA, sandbox, or workspace
configuration. Its filesystem is read-only, capabilities are dropped,
`no-new-privileges:true` is enabled, and its only mounts are the read-only Vault
and OpenSearch CA files.

The one-shot installs and reads back the committed schema-v2 index template and
checks any existing target index mapping. Missing acknowledgement, stale schema,
an incompatible existing index, Vault/authorization failure, or transport error
exits non-zero. API and worker wait for
`service_completed_successfully`, so template provisioning is a mandatory
startup gate and never a manual deployment prerequisite.

### PostgreSQL migration one-shot

`postgres-migrations` runs the packaged
`python /app/scripts/dev/apply_postgres_migrations.py` command exactly once.
It waits for the OpenSearch bootstrap and API/worker wait for its
`service_completed_successfully` result. Production requires the separately
scoped `HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE`; Compose mounts it only inside
the migration service as `HALLU_DEFENSE_POSTGRES_DSN_FILE`. The API and worker retain
their ordinary runtime DSN and never receive the migration credential. The
one-shot is read-only, drops all capabilities, uses `no-new-privileges`, mounts
only a bounded `/tmp` plus the read-only PostgreSQL CA, and inherits the exact
API image. The migration CLI independently enforces the same `verify-full`
policy before opening a connection.

Set the approved HTTPS OIDC issuer and export its real public JWKS before
starting the profile:

```text
python scripts/dev/export_keycloak_jwks.py --output var/keycloak/jwks.json
```

`var/keycloak/jwks.json` is gitignored and mounted read-only at
`/run/hallu-defense/keycloak-jwks.json`.

## Secrets

Vault tokens and PostgreSQL DSNs are file-only in production. Compose receives
four absolute secret paths, never their values, plus one PostgreSQL CA trust
path:

- `HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE`;
- `HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE`, scoped separately from the
  API/worker runtime token;
- `HALLU_DEFENSE_POSTGRES_DSN_FILE`; and
- `HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE`, scoped to schema DDL and mounted
  only into the migration one-shot; and
- `HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH`, mounted read-only into API,
  worker, and migration one-shot. Both DSN files must encode
  `sslmode=verify-full`,
  `sslrootcert=/run/hallu-defense/postgres/ca.crt`, and
  `ssl_min_protocol_version=TLSv1.3`, and `gssencmode=disable`.

On a Linux deployment host, each source must be a regular non-symlink owned by
`root:10001` with mode 0440. Its direct parent must be `root:10001` mode 0750,
and every higher ancestor must be root-owned and not group/other writable.
Compose file-backed secrets are bind mounts and do not honor service-level
`uid`, `gid`, or `mode`, so the host metadata is the security boundary. The
non-root deployment identity must be a member of the host group with GID 10001;
this grants preflight read access without granting directory write access.
Create the directory and group explicitly, start a new login for the membership,
then use the mandatory deployment path:

```text
sudo groupadd --gid 10001 hallu-runtime
sudo usermod --append --groups hallu-runtime hallu-deploy
sudo install -d -o root -g 10001 -m 0750 /run/hallu
sudo install -o root -g 10001 -m 0440 runtime-vault-token /run/hallu/runtime-vault-token
sudo install -o root -g 10001 -m 0440 bootstrap-vault-token /run/hallu/bootstrap-vault-token
sudo install -o root -g 10001 -m 0440 runtime-postgres-dsn /run/hallu/runtime-postgres-dsn
sudo install -o root -g 10001 -m 0440 migrations-postgres-dsn /run/hallu/migrations-postgres-dsn
sudo install -o root -g 10001 -m 0440 postgres-ca.crt /run/hallu/postgres-ca.crt
export HALLU_DEFENSE_RUNTIME_VAULT_TOKEN_FILE=/run/hallu/runtime-vault-token
export HALLU_DEFENSE_BOOTSTRAP_VAULT_TOKEN_FILE=/run/hallu/bootstrap-vault-token
export HALLU_DEFENSE_POSTGRES_DSN_FILE=/run/hallu/runtime-postgres-dsn
export HALLU_DEFENSE_POSTGRES_MIGRATION_DSN_FILE=/run/hallu/migrations-postgres-dsn
export HALLU_DEFENSE_POSTGRES_CA_CERT_HOST_PATH=/run/hallu/postgres-ca.crt
make prod-profile-up
```

`scripts/dev/preflight_runtime_secret_files.py` fails closed unless all four
secret files and the PostgreSQL CA, plus their parent chains, have the exact
ownership/mode and bounded UTF-8 content. It also parses both DSNs and rejects
anything other than `verify-full` with the exact in-container `sslrootcert`.
It also rejects a PostgreSQL minimum TLS version other than `TLSv1.3` or a
DSN that does not disable GSS encryption before enforcing verified TLS.
Run `id hallu-deploy` before deployment and verify GID 10001 is present; do not
use broad `sudo -E` environment preservation.

A Compose file-secret mount remains attached to the original host inode. After
atomically replacing any secret, ServiceAccount token, JWKS, or CA source file,
the operator must recreate the consumers before the old credential expires:

```text
make prod-profile-rotate-secrets
```

That target repeats both preflight and the production config gate, then uses
Compose `--force-recreate`. Merely rewriting or renaming a host file is not
treated as hot rotation. Runtime values still never appear in `docker inspect`
or the process environment.

Provider credentials remain at Vault path `providers/openai/api-key` (or the
configured adapter path). The complete OpenSearch Authorization header remains
at the logical Vault path named by
`HALLU_DEFENSE_OPENSEARCH_AUTHORIZATION_SECRET_NAME`; no plaintext OpenSearch
username, password, API key, token, or Authorization environment variable is
accepted. The Redis URL remains at Vault path
`quotas/tool-validation/redis-url`, must use `rediss://`, and is never placed
directly in Compose.

Do not put production secret values into `.env.example`, shell environment, or
committed Compose files. Local Vault development still uses the existing
local-only helper:

```text
python scripts/dev/bootstrap_local_vault.py
python scripts/dev/live_vault_secrets_smoke.py
```

## Kubernetes Sandbox Credentials

The API talks directly to the approved Kubernetes HTTPS endpoint with the
dedicated ServiceAccount token and CA files mounted read-only at their standard
in-cluster paths. Both files and the endpoint variables are required
interpolations: the profile cannot silently start with anonymous access, a
system trust fallback, or a plaintext control-plane endpoint. The Vault CA is
likewise a required read-only mount rather than an optional host trust
assumption.

Provision the ServiceAccount with minimum RBAC scoped to the configured sandbox
namespace: only the Job, Pod/log, and NetworkPolicy reads and Job lifecycle
operations used by the backend. Bind one tenant to one release and workspace
PVC, use a short-lived projected token, and keep the named default-deny egress
NetworkPolicy in place. The Compose profile consumes these externally managed
Kubernetes resources; Helm creates the equivalent dedicated ServiceAccount,
projected token/CA, PVC, and RBAC resources for cluster deployments.

`HALLU_DEFENSE_ALLOWED_WORKSPACE_HOST` must expose the same tenant-bound
storage represented by `HALLU_DEFENSE_SANDBOX_KUBERNETES_PVC_NAME`; it is
mounted into the API read-only. Each authorized sandbox Job mounts that source
read-only at `/hallu-source`, copies its bounded contents into a per-run
`emptyDir` at `/workspace`, and discards the copy when the Job is removed.
Inspection evidence is returned in memory as `sandbox://inspection`; the
sandbox never writes its inspection report into the source. Do not point the
setting at a generic host checkout or a cross-tenant share.

## Prometheus Credentials

An externally operated Prometheus can use
`infra/prometheus/prometheus.prod.yml`, which reads
the API metrics bearer token via `authorization.credentials_file` at
`/run/secrets/hallu_defense_metrics_bearer_token`. Prometheus is deliberately
not started by the production Compose merge; its deployment must mount the
credential file and target the API through the approved network boundary.
Inline Prometheus credentials remain rejected by the static gate.

## Live E2E Scaffold

`scripts/dev/live_prod_profile_e2e.py` is disabled by default. When
`HALLU_DEFENSE_LIVE_PROD_PROFILE_E2E_ENABLED=true`, it expects a deployed API
URL and a real OIDC bearer token, then checks auth, verification, approval,
grant consumption, sandbox, corpus grants, eval report publish/list, audit
export, and metrics. Provider connectivity and the Batch 6 ingestion worker
runtime require their dedicated live smokes; this script does not claim them.
The script remains env-gated and does not turn a skipped run into live evidence.
