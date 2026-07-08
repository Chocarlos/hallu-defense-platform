# ADR 0002: Data Plane And Control Plane

## Status

Accepted for foundation.

## Context

Sensitive documents, repo state, sandbox execution, and tenant data may need to stay local/on-prem. Operational dashboards and aggregate evals may run centrally.

## Decision

Separate:

- Data plane: local documents, indexes, sandbox, secrets, audit ledger, and tenant data.
- Control plane: optional console, aggregate metrics, eval summaries, policy administration.

## Consequences

- Local deployments can operate without sending sensitive data to a SaaS control plane.
- APIs must be tenant-aware from the beginning.
- Audit and eval exports must support redaction/minimization.

