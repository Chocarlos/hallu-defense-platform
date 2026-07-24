## Summary

Describe the problem, the selected scope, and the resulting behavior. Keep the change bounded and identify what is intentionally out of scope.

## Risk and compatibility

- Risk level: `low` / `medium` / `high` / `critical`
- Runtime behavior changed: `yes` / `no`
- Public contract changed: `yes` / `no`
- Migration required: `yes` / `no`
- Security boundary changed: `yes` / `no`

Explain every `yes` answer and identify affected tenants, APIs, schemas, providers, policies, persistence, sandbox, deployment, or observability surfaces.

## Implementation

List the important files and design decisions. Link the relevant requirement, issue, ADR, or traceability entry when one exists.

## Validation evidence

Provide the exact commands executed and summarize their results. Do not claim a test, build, live smoke, deployment, provider, browser, or environment passed unless it was actually executed against this commit.

```text
# command
# result
```

## Security and privacy

- [ ] No secrets, credentials, tokens, private keys, tenant data, or sensitive logs are included.
- [ ] New outbound destinations are explicitly allowlisted and redirects remain fail-closed.
- [ ] Authentication, authorization, tenant isolation, rate limits, approvals, and audit behavior remain correct or are covered by new tests.
- [ ] Third-party material has documented origin, license compatibility, and required attribution.
- [ ] High-risk behavior has deterministic evidence and does not rely only on model output.

Mark non-applicable items explicitly in the explanation rather than silently ignoring them.

## Contracts and documentation

- [ ] Pydantic, TypeScript, JSON Schema, OpenAPI, SDK, and examples are synchronized when a public contract changes.
- [ ] `docs/TRACEABILITY_MATRIX.md` is updated when a requirement changes.
- [ ] `docs/WORKLOG.md` records meaningful implementation and validation work.
- [ ] `CHANGELOG.md` is updated for user-visible, compatibility, or security-relevant changes.
- [ ] Documentation describes remaining limitations without upgrading `tested` evidence to `accepted`.

## Reviewer focus

Call out the highest-risk assumption, the most important regression to look for, and any validation that still requires an external environment or independent operator.
