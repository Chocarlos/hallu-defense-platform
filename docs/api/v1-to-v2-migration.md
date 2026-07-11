# Public contract migration: v1 to v2

## Compatibility policy

Version 2 is additive. Existing v1 routes, payload fields, enum values, and
serialization order remain unchanged. The six core v1 contracts (`Claim`,
`Evidence`, `ClaimVerdict`, `VerificationRun`, `ToolCallEnvelope`, and
`SandboxRun`) declare `x-contract-version: "1.0"` in Pydantic-generated schema,
JSON Schema, and OpenAPI metadata. This metadata is not a response field and
therefore does not change v1 payload bytes.

Version 2 currently adds these routes:

- `POST /v2/claims/verify`
- `POST /v2/verification/run`

Every v2 request and response requires `schema_version: "2.0"`. Each nested
`ClaimVerdictV2` also carries that field, and all five v2 schemas declare
`x-contract-version: "2.0"` metadata. Missing, legacy, or unknown versions fail
request validation; clients must not silently downgrade.

The v2 routes use the same verifier/orchestrator, trace propagation, audit
middleware, tenant boundary, and `verifier` RBAC role as v1. A body `tenant_id`
that differs from the authenticated/header tenant is rejected with 403.

## Verdict status mapping

Conversion evaluates human review first, then a structurally proven policy
block, then the total legacy-status mapping below.

| v1 status | v2 status |
|---|---|
| `SUPPORTED` | `supported` |
| `PARTIALLY_SUPPORTED` | `insufficient_evidence` |
| `CONTRADICTED` | `contradicted` |
| `NOT_FOUND` | `unsupported` |
| `AMBIGUOUS` | `insufficient_evidence` |
| `STALE_SOURCE` | `insufficient_evidence` |
| `UNVERIFIABLE` | `not_verifiable` |
| `OUT_OF_SCOPE` | `not_verifiable` |

`require_human_review` always becomes status `requires_human_review`. A v1
`block` becomes status `blocked_by_policy` only when `validator_trace` contains
both a non-empty string `policy_version` and a non-empty list of non-empty
string `matched_rules`. Action `block` alone is not policy evidence: a generic
high-risk or contradiction block retains the status from the table and uses the
v2 `block` action.

## Verdict action mapping

| v1 action | v2 action |
|---|---|
| `allow` | `allow` |
| `allow_with_citation` | `allow` |
| `rewrite` | `repair` |
| `abstain` | `abstain` |
| `ask_clarification` | `ask_clarification` |
| `block` | `block` |
| `require_human_review` | `require_approval` |

The v2 contract rejects inconsistent pairs: `blocked_by_policy` requires
`block`; `requires_human_review` and `require_approval` must appear together.
`final_decision` retains the existing values because it describes the completed
run, while `action` describes what to do for an individual claim.

## SDK migration

The TypeScript SDK preserves `runVerification` and `verifyClaims` for v1 and
adds explicit versioned methods:

```ts
const run = await client.runVerificationV2({
  schema_version: "2.0",
  message_text: "The response to verify."
});

const response = await client.verifyClaimsV2({
  schema_version: "2.0",
  claims,
  evidence
});
```

Do not translate enum labels in UI code. Consume the exported
`VerdictStatusV2`, `VerdictActionV2`, `ClaimVerdictV2`, and `VerificationRunV2`
types so unknown future values cause a compile-time or validation failure.

## Drift prevention

`packages/contracts/contract-versions.json` is the semantic manifest. The
`check_contract_versions.py` gate compares public fields, required v2 fields,
versions, enum vocabularies, and route request/response models across Pydantic,
TypeScript, JSON Schema, and the committed OpenAPI document. It also locks the
six core v1 payload shapes and version metadata. JSON Schema valid/invalid
examples and byte snapshots provide executable compatibility evidence.
