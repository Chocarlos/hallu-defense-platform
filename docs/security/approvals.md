# Approval Queue

The API approval workflow supports two queue backends:

- `memory`: local/test-only process memory for fast development.
- `jsonl`: append-only JSON Lines storage for approval request and decision snapshots.

Production and staging must not use `memory`; `create_approval_queue()` rejects that
configuration at startup. Use:

```text
HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND=jsonl
HALLU_DEFENSE_APPROVAL_QUEUE_PATH=var/approvals/approval-queue.jsonl
HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS=900
```

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
