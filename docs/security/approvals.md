# Approval Queue

The API approval workflow supports three queue backends:

- `memory`: local/test-only process memory for fast development.
- `jsonl`: append-only JSON Lines storage for approval request and decision snapshots.
- `postgres` (alias `postgresql`): durable relational storage whose single-use guards
  are enforced by the database, for multi-worker deployments.

`memory` and `jsonl` are local/single-process development backends.
Production and staging require PostgreSQL; `create_approval_queue()` rejects every other backend at
startup because file locking cannot provide global decide-once/consume-once semantics.
Use:

```text
HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND=postgres
HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS=900
HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME=approvals/tool-call-commitment-key
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_BACKEND=redis
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS=120
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS=60
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL_SECRET_NAME=quotas/tool-validation/redis-url
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_TIMEOUT_SECONDS=1
```

## Tool Validation Rate Limit

`POST /tools/validate-input` and `POST /tools/validate-output` apply the fixed-window
rate limit before OPA or approval/grant handling. The limit is scoped by tenant,
authenticated subject, normalized tool name, and phase (`input` or `output`), so one
tenant, agent, tool, or phase cannot consume another scope's budget. Approved
execution grants remain subject to this limiter; review does not create a quota bypass.

The `memory` backend is thread-safe but process-local and is restricted to local/test
use. Production and staging require `backend=redis`. The Redis backend executes one
atomic Lua `INCR` + `PEXPIRE` operation, so all API replicas share the same limit and a
replica restart does not reset it. Redis keys contain a SHA-256 digest of the scope,
not readable tenant, subject, or tool values.

Production and staging resolve the Redis URL from SecretManager/Vault using the
configured logical secret name. The resolved URL must use `rediss://`, the CA path is
required, certificate verification remains mandatory, and network operations use the
configured short timeout without automatic retry. A Redis outage produces a generic
HTTP 503 before an approval can be created and makes `/ready` fail while `/health`
remains a liveness check. The URL and credentials are never included in errors or
metrics.

For an opt-in smoke against a local Redis only, set
`HALLU_DEFENSE_LIVE_REDIS_RATE_LIMIT_SMOKE_ENABLED=true` and the local/test-only direct
`HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_REDIS_URL`, then run
`python scripts/dev/live_redis_rate_limit_smoke.py`. The smoke uses two independent
clients, a concurrent burst, tenant isolation, and TTL expiration.

## Minimization

The JSONL backend stores redacted `ApprovalRecord` snapshots. Sensitive-looking keys
and values inside tool input, tool schema, caller context, request reason, and decision
reason are recursively redacted before storage. Exact sensitive keys such as
`api_key`, `secret`, `token`, or `password` are covered. This also includes private keys/PEM,
access/API keys, credentials, payment cards, passport, DOB, address, email, SSN, and
phone values, including numeric keyed PII and compact values only when explicitly
labeled. Signed-URL query credentials, Azure SAS/SharedAccessSignature,
AccountKey/SharedAccessKey, authorization/proxy-authorization headers, and complete
cookie/set-cookie lines are removed without discarding unrelated URL parameters. The
same bounded normalizer covers structured header paths and the `X-Goog-Signature`,
`X-Amz-Security-Token`, `X-Goog-Credential`, `X-API-Key`, `X-Access-Token`, and
`X-Auth-Token` aliases in query strings, headers, mappings, and serialized JSON. Safe
policy/preferences keys and nonsensitive X-Goog metadata remain visible.
Non-finite numbers, cycles, and unsupported values fail closed. Traversal is bounded by depth, node,
container, string, number, and total-text limits; cycles or overflow reject the
request before persistence rather than storing a partial snapshot. Tenant and trace
identifiers remain available for correlation.

For post-tool validation, the raw value must first satisfy the trusted output schema.
After recursive redaction, the API validates the sanitized value against that same
server-bound schema again. A schema-compatible marker may be released as a rewrite;
if a format, pattern, type, enum, or const rejects the actual marker, the result is a
block with no `sanitized_output`. The original is never substituted back into the
response. Invalid Unicode surrogates, non-finite numbers, incomplete JSON rewrites,
and traversal-limit failures follow the same fail-closed path.

Before redaction, the queue resolves the tool through the immutable server registry
and computes an opaque v3, domain-separated commitment over an explicit approval
binding: the generated `approval_id`, originating trace ID, authenticated tenant and
subject, canonical tool name and policy action, SHA-256 of canonical arguments, plus
trusted definition version and digest. The record ID is generated before the binding,
so two reviews of otherwise identical facts have distinct commitments. Public schema, risk, approval,
side-effect, action, identity, and approval-status assertions are never authority.
The argument hash is calculated from the original unredacted canonical arguments;
the persisted reviewer snapshot remains redacted and cannot be used to recreate authority.
Unknown tools, mismatches, malformed canonical JSON, or definitions that do not
require approval fail closed. Production and staging require a
stable 32-byte-or-longer HMAC key resolved from the logical
`HALLU_DEFENSE_APPROVAL_TOOL_CALL_COMMITMENT_SECRET_NAME` through the Vault
`SecretManager`; raw key environment variables are not accepted. Only local/test
instances with no logical secret name may use the explicit domain-separated SHA-256
fallback. Only the prefixed commitment is persisted as private approval metadata. It
is excluded from REST/OpenAPI serialization, and neither the original payload nor an
execution token is written or logged.

On upgrade from the earlier redacted-fingerprint format, unconsumed legacy grants
are intentionally invalidated. Pending records that predate the private commitment
must be rejected or requested again before approval; the service never falls back to
binding a new grant to a redacted snapshot. A queue running with an HMAC key also
refuses to approve any persisted pending record whose commitment has the legacy
`sha256:` prefix; only `hmac-sha256:` can produce a production execution grant.

## Replay Model

The queue writes one append-only record when an approval is requested and another
append-only record when it is approved or rejected. On startup, the queue replays the
JSONL file and keeps the latest snapshot per `approval_id`.

Approved decisions also issue a bounded execution grant. The API returns the grant's
opaque `approval_execution_token` only to the approval caller, stores only a hash of
that token, and binds the grant to the tenant, `approval_id`, v3 approval binding, and
expiration time. Changing authenticated subject, tool/action, canonical arguments, or
trusted definition version/digest invalidates it. Definition rotation invalidates both
pending approvals and already issued unconsumed grants. Reviewer-visible schemas may
contain redaction markers and are display snapshots only; execution always re-resolves
the current server definition.

An executor must present the grant on a second `/tools/validate-input` call using the
same canonical tool assertions plus `approval_id` and `approval_execution_token`. A valid grant is
consumed exactly once and produces a process-local, issuer-bound capability that
ToolSafety accepts once; the public contract cannot assert that capability. Missing,
expired, reused, wrong-tenant, or
wrong-subject, mismatched-tool/action/arguments, or stale-definition grants fail closed.

Corrupt records, unsupported record types, or malformed payloads fail closed at
startup. That prevents the API from serving a partially trusted approval state.

## PostgreSQL Backend

The `postgres` backend stores approvals in `approval_records` and execution grants in
`approval_execution_grants`. The redacted `ApprovalRecord` snapshot is persisted as
`jsonb`, so the same minimization applies as with `jsonl`: sensitive-looking keys are
`[REDACTED]` and only the token hash (never the raw execution token) is written.

`create_approval_queue(settings, sql_provider=...)` selects this backend and fails
closed when `approval_queue_backend` is `postgres`/`postgresql` but no
`SqlConnectionProvider` is injected. The provider is the audited SQL seam from
`hallu_defense.services.postgres`; the approval queue never imports a driver directly.

Two invariants are enforced by the database, so concurrent API workers cannot
double-decide or double-spend, even without an application lock:

- **atomic decision and grant:** one `SqlConnectionProvider.transaction()` contains the
  decide-once `UPDATE approval_records SET status=…, decided_at=…, payload=…::jsonb
  WHERE approval_id=… AND tenant_id=… AND status='pending' RETURNING approval_id`. Zero
  rows returned means the approval was already decided (HTTP 409 equivalent) and raises
  `ApprovalAlreadyDecidedError`. For approval, the execution-grant `INSERT` runs on that
  same transaction-bound provider; any insert or commit failure rolls the decision back
  to `pending`, so an approved record can never become visible without its grant. The
  reviewer-identity and not-found checks keep the same taxonomy as the JSONL backend.
- **consume-once:** `UPDATE approval_execution_grants SET consumed_at=now()
  WHERE token_hash=… AND tenant_id=… AND tool_call_fingerprint=… AND consumed_at IS NULL
  AND expires_at > now() RETURNING approval_id`. Zero rows means the grant cannot be
  spent; a disambiguation `SELECT` maps the reason to the existing errors — consumed,
  expired, or invalid/mismatched (HTTP 403 equivalent).

The token hash is `sha256(token)` exactly as with the other backends, and the v3
approval commitment binds each grant to the reviewed authorization facts, so a valid grant
authorizes one exact matching tool call once and only once.

## Reviewer Identity

Approval decisions are authorized through the request principal documented in
`docs/security/auth-rbac.md`. `POST /approvals/decide` requires the
`approval_reviewer` role and records `decided_by` from `x-subject-id`; the request
body field is ignored by the API route and remains only as a deprecated
compatibility field.

## Validation

`scripts/ci/check_approval_queue_config.py` validates the configuration surface and
CI wiring. `apps/api/tests/test_approval_queue.py` verifies append-only persistence,
reload, tenant isolation, execution grant hashing, single-use consumption, expiration,
repeated-decision blocking, redaction, secret-substitution rejection, pooled-provider
rollback/concurrency, production startup rejection for process-local `memory` and
`jsonl`, and fail-closed corrupt-record handling.
