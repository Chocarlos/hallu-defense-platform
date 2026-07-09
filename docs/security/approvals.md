# Approval Queue

The API approval workflow supports three queue backends:

- `memory`: local/test-only process memory for fast development.
- `jsonl`: append-only JSON Lines storage for approval request and decision snapshots.
- `postgres` (alias `postgresql`): durable relational storage whose single-use guards
  are enforced by the database, for multi-worker deployments.

Production and staging must not use `memory`; `create_approval_queue()` rejects that
configuration at startup. Use:

```text
HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND=jsonl
HALLU_DEFENSE_APPROVAL_QUEUE_PATH=var/approvals/approval-queue.jsonl
HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS=900
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_MAX_REQUESTS=120
HALLU_DEFENSE_TOOL_VALIDATION_RATE_LIMIT_WINDOW_SECONDS=60
```

## Tool Validation Rate Limit

`POST /tools/validate-input` applies an in-memory fixed-window rate limit before
creating new approval requests or allowing low-risk calls. The limit is scoped by
tenant, authenticated subject, and tool name, so one tenant or agent cannot consume
another tenant's budget. Approved execution grants bypass this limiter because they
have already been reviewed, are fingerprint-bound, and are consumed once.

## Minimization

The JSONL backend stores redacted `ApprovalRecord` snapshots. Sensitive-looking keys
inside tool input, tool schema, and caller context are replaced with `[REDACTED]`
before storage. Tenant and trace identifiers remain available so reviewers and audits
can correlate a decision without persisting raw secrets.

## Replay Model

The queue writes one append-only record when an approval is requested and another
append-only record when it is approved or rejected. On startup, the queue replays the
JSONL file and keeps the latest snapshot per `approval_id`.

Approved decisions also issue a bounded execution grant. The API returns the grant's
opaque `approval_execution_token` only to the approval caller, stores only a hash of
that token, and binds the grant to the tenant, `approval_id`, tool name, sanitized tool
input/schema/context fingerprint, and expiration time.

An executor must present the grant on a second `/tools/validate-input` call using the
same tool envelope plus `approval_id` and `approval_execution_token`. A valid grant is
consumed exactly once and returns `allow`; missing, expired, reused, wrong-tenant, or
mismatched-tool grants fail closed.

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

Two invariants are enforced by the database as single-statement guards, so concurrent
API workers cannot double-decide or double-spend, even without an application lock:

- **decide-once:** `UPDATE approval_records SET status=…, decided_at=…, payload=…::jsonb
  WHERE approval_id=… AND tenant_id=… AND status='pending' RETURNING approval_id`. Zero
  rows returned means the approval was already decided (HTTP 409 equivalent) and raises
  `ApprovalAlreadyDecidedError`. The reviewer-identity and not-found checks keep the same
  taxonomy as the JSONL backend.
- **consume-once:** `UPDATE approval_execution_grants SET consumed_at=now()
  WHERE token_hash=… AND tenant_id=… AND tool_call_fingerprint=… AND consumed_at IS NULL
  AND expires_at > now() RETURNING approval_id`. Zero rows means the grant cannot be
  spent; a disambiguation `SELECT` maps the reason to the existing errors — consumed,
  expired, or invalid/mismatched (HTTP 403 equivalent).

The token hash is `sha256(token)` exactly as with the other backends, and the tool-call
fingerprint binds each grant to its sanitized envelope, so a valid grant authorizes one
matching tool call once and only once.

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
repeated-decision blocking, redaction, production startup rejection for `memory`, JSONL
acceptance in production, and fail-closed corrupt-record handling.
