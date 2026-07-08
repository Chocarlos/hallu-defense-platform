# ADR 0006: Policy Engine

## Status

Accepted for foundation.

## Context

Some decisions are deterministic policy decisions, not LLM judgments: tenant access, approvals, tool risk, secret leakage, sandbox network, and repository evidence rules.

## Decision

Use two policy layers:

- OPA/Rego for access, risk, and approval policies.
- Python domain rules for versioned business logic and explainable local decisions.

## Consequences

- Every policy decision must include policy version, decision, reason, rule identifiers, and trace ID.
- The current Python policy engine enforces the initial deterministic rule set for `/policy/evaluate`.
- Rego policy and test files exist as the formal policy baseline.
- The API has an optional OPA adapter that executes `opa eval` when `HALLU_DEFENSE_OPA_ENABLED=true` and an OPA binary is available.
- If OPA is enabled but evaluation fails, policy evaluation fails closed with `opa_policy_evaluation_failed`.
- CI installs OPA before policy tests; local development without OPA falls back to static Rego structure checks and still executes Python policy endpoint tests.
