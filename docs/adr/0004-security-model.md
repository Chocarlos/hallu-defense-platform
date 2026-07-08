# ADR 0004: Security Model

## Status

Accepted for foundation.

## Context

The platform processes untrusted prompts, documents, tool outputs, repository content, and command output. It must assume prompt injection, secret leakage, tenant boundary mistakes, and unsafe tool use.

## Decision

Security defaults:

- Tenant context required on requests.
- OIDC-ready auth boundary.
- RBAC/ABAC-ready policy engine.
- High-risk actions require approval.
- Secret-like output is redacted.
- Audit ledger records decisions.
- Egress is denied by default for sandboxed code-agent work.

## Consequences

- Local development can run with minimal auth, but production must enable auth and policy enforcement.
- Logging must prefer references and redacted summaries over raw sensitive content.

