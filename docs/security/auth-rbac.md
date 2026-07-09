# Authentication and RBAC Boundary

The authoritative config baseline is `infra/security/auth-policy.json`. The CI
gate `scripts/ci/check_auth_config.py` validates the policy, environment example,
runtime fail-closed checks, role matrix wiring, and CI/security workflow wiring.

The API builds a request principal either from an in-process OIDC JWT validator
or from trusted boundary headers supplied by a gateway/local development tooling:

```text
Authorization: Bearer ...
x-subject-id: reviewer-123
x-roles: approval_reviewer,reader
```

`HALLU_DEFENSE_AUTH_REQUIRED=true` makes `Authorization` and `x-subject-id`
mandatory. Without a subject, the principal is anonymous and has no roles. Roles
are parsed from comma- or whitespace-separated values.

`HALLU_DEFENSE_AUTH_CLAIMS_MODE` controls how the API trusts those boundary
headers:

- `unsigned_headers`: local/default mode. Headers are parsed but not
  cryptographically verified.
- `signed_headers`: trusted gateway mode. The API verifies an HMAC-SHA256
  signature before trusting `x-subject-id`, `x-roles`, or `x-tenant-id`.
- `oidc_jwt`: in-process OIDC JWT mode. The API verifies an `Authorization`
  bearer JWT against a configured JWKS file before deriving subject, roles, and
  tenant from token claims.

OIDC JWT mode expects:

```text
Authorization: Bearer <OIDC JWT>
```

Configured through:

```text
HALLU_DEFENSE_AUTH_CLAIMS_MODE=oidc_jwt
HALLU_DEFENSE_OIDC_ISSUER=https://issuer.example
HALLU_DEFENSE_OIDC_AUDIENCE=hallu-defense-api
HALLU_DEFENSE_OIDC_JWKS_PATH=/run/secrets/oidc-jwks.json
HALLU_DEFENSE_OIDC_JWKS_URL=https://issuer.example/jwks.json
HALLU_DEFENSE_OIDC_DISCOVERY_URL=https://issuer.example/.well-known/openid-configuration
HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS=300
HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS=3
HALLU_DEFENSE_OIDC_SUBJECT_CLAIM=sub
HALLU_DEFENSE_OIDC_ROLES_CLAIM=roles
HALLU_DEFENSE_OIDC_TENANT_CLAIM=tenant_id
HALLU_DEFENSE_OIDC_CLOCK_SKEW_SECONDS=60
```

JWKS can come from one of three sources:

- `HALLU_DEFENSE_OIDC_JWKS_PATH`: local file, suitable for mounted secret/config
  files.
- `HALLU_DEFENSE_OIDC_JWKS_URL`: direct remote JWKS endpoint.
- `HALLU_DEFENSE_OIDC_DISCOVERY_URL`: OIDC discovery document containing
  `issuer` and `jwks_uri`.

The remote resolver caches JWKS responses for
`HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS`. If a JWT presents an unknown `kid`,
the API refreshes JWKS once before rejecting the token, which supports normal key
rotation without turning every request into a network call. Production and
staging require HTTPS for remote JWKS and discovery URLs.

The validator accepts only `RS256` JWTs with a `kid` that maps to a usable RSA
signing key in JWKS. It verifies the JWT signature, issuer, audience, required
`exp`, optional `nbf`/`iat` with configured skew, a non-empty subject claim, and a
non-empty tenant claim. The roles claim can be a string or a string array. If
`x-tenant-id` is also sent, it must match the token tenant claim.

After a request is authenticated, the API stores the verified tenant in request
state. The HTTP audit middleware uses that authenticated tenant for the
`http_request` audit event, so `oidc_jwt` requests without `x-tenant-id` are
audited under the JWT tenant instead of the local/header fallback.

Signed mode expects:

```text
x-auth-claims-timestamp: <unix epoch seconds>
x-auth-claims-signature: v1=<hex hmac sha256>
```

The signature is computed over a canonical payload containing signature version,
tenant ID, subject ID, sorted roles, and timestamp. The signing key is read
through `SecretManager` using `HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_SECRET_NAME`.
`HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_TOLERANCE_SECONDS` bounds clock skew and
replay age.

Signed mode is a trusted gateway claims-validation path. Use it only when an
OIDC-aware gateway performs JWT verification before injecting and signing
claims. Do not expose unsigned claim headers directly to untrusted clients.

## Approval Reviewer Role

`POST /approvals/decide` requires the `approval_reviewer` role. Anonymous callers
or authenticated callers without that role receive `403`.

The route derives reviewer identity from the authenticated principal and writes
that subject into the approval decision. `ApprovalDecisionRequest.decided_by` is
kept optional for compatibility but is deprecated at the API boundary; submitted
body values are ignored by `/approvals/decide`.

The approval service still rejects direct decision calls that do not include a
reviewer identity, so bypassing the route does not create anonymous decisions.

## Endpoint Role Matrix

When `HALLU_DEFENSE_AUTH_REQUIRED=true`, API routes guarded by
`ENDPOINT_ROLE_REQUIREMENTS` require one of the listed roles. `admin` satisfies all
role requirements.

| Endpoint | Required role |
|---|---|
| `GET /metrics` | `metrics_reader` |
| `POST /claims/extract` | `verifier` |
| `POST /claims/classify` | `verifier` |
| `POST /evidence/retrieve` | `verifier` |
| `POST /documents/ingest` | `rag_writer` |
| `POST /rag/corpus-grants/upsert` | `rag_writer` |
| `POST /rag/corpus-grants/disable` | `rag_writer` |
| `POST /rag/corpus-grants/list` | `rag_writer` or `verifier` |
| `POST /rag/corpus-grants/history` | `rag_writer` or `verifier` |
| `POST /rag/corpus-grants/history/diff` | `rag_writer` or `verifier` |
| `POST /claims/verify` | `verifier` |
| `POST /response/repair` | `verifier` |
| `POST /tools/validate-input` | `tool_operator` |
| `POST /tools/validate-output` | `tool_operator` |
| `POST /policy/evaluate` | `policy_evaluator` |
| `POST /approvals/list` | `approval_reviewer` |
| `POST /approvals/decide` | `approval_reviewer` |
| `POST /repo/checks/run` | `sandbox_runner` |
| `POST /audit/export` | `auditor` |
| `POST /verification/run` | `verifier` |
| `POST /verification/replay` | `verifier` |

`POST /verification/replay` only replays `VerificationRun` snapshots that the
audit ledger returns for the authenticated tenant. Missing traces and
cross-tenant traces fail closed with the same `404` response, and the replay
re-executes verification/repair over the redacted stored snapshot instead of
echoing live payloads.

Local development with `HALLU_DEFENSE_AUTH_REQUIRED=false` bypasses this matrix
except for `POST /approvals/decide`, `POST /rag/corpus-grants/upsert`,
`POST /rag/corpus-grants/disable`, `POST /rag/corpus-grants/list`, and
`POST /rag/corpus-grants/history`, and
`POST /rag/corpus-grants/history/diff`; those routes always require an
authenticated principal with one of their listed roles because they mutate or
expose authorization state.

Production and staging must set:

```text
HALLU_DEFENSE_AUTH_REQUIRED=true
HALLU_DEFENSE_AUTH_CLAIMS_MODE=oidc_jwt
HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME=observability/metrics-bearer-token
```

`load_settings()` rejects production-like environments that leave auth optional
or trust unsigned claim headers. The runtime also permits `signed_headers` as a
fail-closed trusted-gateway mode, but the enterprise auth policy baseline
requires `oidc_jwt`.

## Authenticated `/metrics` Scrape Path

`GET /metrics` accepts either an authenticated `metrics_reader` principal through
the normal OIDC/RBAC flow or a static Prometheus scrape token:

```text
Authorization: Bearer <metrics scrape token>
HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME=observability/metrics-bearer-token
```

The static token value is loaded through `SecretManager` using the configured
secret name and compared with `hmac.compare_digest` for constant-time equality.
A match grants a synthetic `metrics_reader` principal for `GET /metrics` only.
Every other route keeps using the existing request-context and endpoint-role
matrix; the metrics bearer token does not grant audit, verification, approval,
RAG, policy, or sandbox access.

The bearer-token path fails closed:

- If the secret name is unset in local/dev/test/CI, the bearer-token shortcut is
  disabled and `/metrics` falls back to the existing auth/RBAC behavior.
- If the secret cannot be loaded, the bearer-token shortcut does not grant
  access.
- Production and staging reject startup unless
  `HALLU_DEFENSE_METRICS_BEARER_TOKEN_SECRET_NAME` is configured and the secret
  backend is not `env`.
- When `HALLU_DEFENSE_AUTH_REQUIRED=true`, callers without either a matching
  scrape token or `metrics_reader` role receive `401`/`403`; there is no
  default-allow production scrape mode.

`infra/prometheus/prometheus.prod.yml` uses Prometheus
`authorization.credentials_file`, so the deployed scrape token is mounted as a
file and is not committed in Prometheus config or exposed as a process argument.

## RAG Corpus Grants And Metadata ABAC

RAG corpora remain tenant-scoped. The API does not grant cross-tenant corpus
sharing; persistent RAG backends still filter by the authenticated tenant.

Within a tenant, operators can manage durable corpus grants through:

- `POST /rag/corpus-grants/upsert`: creates or replaces reader/writer roles for
  the authenticated tenant and requested `corpus_id`; requires `rag_writer` even
  when local auth is optional.
- `POST /rag/corpus-grants/disable`: logically disables the active grant for the
  authenticated tenant and requested `corpus_id`; requires `rag_writer` even
  when local auth is optional. Disabled grants do not enforce reader/writer roles
  and are retained as append-only audit state.
- `POST /rag/corpus-grants/list`: lists grants for the authenticated tenant;
  supports `corpus_id`, `include_disabled`, `limit`, and `cursor`; requires
  `rag_writer` or `verifier` even when local auth is optional.
- `POST /rag/corpus-grants/history`: lists append-only grant revisions for the
  authenticated tenant; supports `corpus_id`, `actor_id`, `updated_at_from`,
  `updated_at_to`, `limit`, and `cursor`; requires `rag_writer` or `verifier`
  even when local auth is optional. `actor_id` filters by the revision
  `updated_by` value, and timestamp filters apply to `updated_at`.
- `POST /rag/corpus-grants/history/diff`: lists append-only revision diffs for
  the authenticated tenant with the same filters as `/history`; each item
  reports `action`, `previous_version`, changed role sets, disabled-state
  changes, `updated_by`, and `updated_at`; requires `rag_writer` or `verifier`
  even when local auth is optional.

The grant registry supports `memory` for local/test use, append-only `jsonl`
storage for durable local deployments, and an injectable PostgreSQL storage
adapter for distributed deployments:

```text
HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=jsonl
HALLU_DEFENSE_CORPUS_GRANTS_PATH=var/rag/corpus-grants.jsonl
```

```text
HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=postgres
HALLU_DEFENSE_POSTGRES_DSN=postgresql://hallu:hallu@postgres:5432/hallu_defense
HALLU_DEFENSE_CORPUS_GRANTS_TABLE_NAME=rag_corpus_grants
```

Production and staging reject the `memory` backend at startup. A malformed JSONL
grant record is treated as untrusted state and fails closed instead of silently
dropping permissions. PostgreSQL-backed deployments use
`infra/rag/pgvector/002_rag_corpus_grants.sql`, which creates an append-only
`rag_corpus_grants` table with tenant/corpus/version primary key and a
monotonic `sequence_id` used to replay audit history in insertion order.

The Python adapter accepts an injected `CorpusGrantSqlConnection` for tests and
custom deployments. When `HALLU_DEFENSE_POSTGRES_DSN` is configured, runtime
wiring uses `PsycopgCorpusGrantSqlConnection`, a lazy psycopg-backed wrapper
that opens driver connections with `dict_row`, executes only parameterized SQL,
and returns mapping rows to the same append-only storage adapter. The domain
registry remains independent from psycopg, so deployments can still inject a
pool-backed adapter when they need different connection lifecycle behavior.

`scripts/ci/check_corpus_grants_config.py` validates the corpus grants env keys,
PostgreSQL migration, fail-closed service behavior, endpoint role matrix,
lifecycle docs, Makefile target, and CI/security workflow wiring.

Each grant carries a monotonically increasing `version`. Upsert re-enables a
disabled grant while preserving original `created_by`/`created_at`; disable
increments the version and records `disabled_by`/`disabled_at`. Repeating disable
for an already disabled grant is idempotent and returns the current disabled
grant without appending a new record.

The history endpoint returns revisions in append order and never returns grants
from another tenant. Timestamp filters must include an explicit timezone offset.

Mutating requests can include `expected_version` for optimistic concurrency.
For create-only upserts, `expected_version: 0` means "only create if no current
grant exists"; for updates and disables the value must match the current grant
`version`. Stale versions fail with `409 Conflict` and do not append a new JSONL
record. Omitting `expected_version` preserves backward-compatible last-write
behavior for local automation.

Document metadata can still declare per-chunk corpus role gates:

```json
{
  "corpus_reader_roles": ["hr_corpus_reader"],
  "corpus_writer_roles": ["hr_corpus_writer"]
}
```

`POST /documents/ingest` rejects documents whose reserved tenant metadata names a
different tenant, whose `corpus_id` metadata conflicts with the request
`corpus_id`, whose `corpus_writer_roles` do not match the authenticated
principal roles, or whose durable grant registry writer roles are missing from
the principal. Successful ingestion stamps `owner_tenant_id` and `corpus_id`
into each indexed chunk.

`POST /evidence/retrieve` rejects inline documents with unreadable
`corpus_reader_roles` and filters persistent evidence chunks whose metadata
requires reader roles the principal does not have. For persistent chunks that
include `metadata.corpus_id`, retrieval also applies durable registry reader
roles. The `admin` role satisfies all corpus reader/writer role checks.

## Deployed Provider Smoke

CI and the security workflow run `scripts/ci/oidc_provider_smoke.py`. By default
it skips without network access:

```text
HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED=false
```

To validate a deployed identity provider, set:

```text
HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED=true
HALLU_DEFENSE_OIDC_ISSUER=https://issuer.example
HALLU_DEFENSE_OIDC_AUDIENCE=hallu-defense-api
HALLU_DEFENSE_OIDC_DISCOVERY_URL=https://issuer.example/.well-known/openid-configuration
HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_JWT=<short-lived test JWT>
HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_SUBJECT=
HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_EXPECTED_TENANT=
HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_REQUIRED_ROLE=
```

`HALLU_DEFENSE_OIDC_JWKS_URL` can be used instead of discovery. The smoke command
does not print the JWT or raw claims; it reports only pass/fail status and the
issuer/source used.

## Current Gaps

- Tenant identity is JWT-derived in `oidc_jwt` mode and header-derived only in
  local/trusted-gateway modes.
- Deployed identity-provider smoke requires externally supplied provider URL and
  short-lived test JWT. Local CI executes the gate in skipped mode.
- Future work can expand ABAC conditions into environment and resource
  sensitivity. Corpus grants now have a default PostgreSQL DSN path; high-throughput
  deployments should still inject a pooled connection adapter.
