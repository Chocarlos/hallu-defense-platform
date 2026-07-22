# Project Brief

Status: canonical orientation brief for scoped development work.

## Mission

Build an enterprise anti-hallucination platform for LLMs and agents. The system
must verify claims and agent actions with deterministic evidence, not plausible
summaries. Every decision must be traceable to contracts, evidence, policy,
validator output, audit events, and validation commands.

The end state is a provider-agnostic, hybrid/local-first-capable product that
can defend:

1. LLM responses.
2. Atomic claims inside generated responses.
3. Agent tool calls before and after execution.
4. Code-agent claims about repositories, files, functions, diffs, tests, and
   builds.

## Non-Negotiable Operating Rules

- Read `AGENTS.md`, `docs/PLAN_MASTER.md`,
  `docs/TRACEABILITY_MATRIX.md`, `docs/WORKLOG.md`, and this brief before
  proposing or editing anything.
- Inspect the current repository state before relying on this brief. This brief
  is orientation; repository evidence wins when there is a conflict.
- Work in the next smallest vertical slice. Do not perform broad rewrites.
- Do not claim files, tests, builds, functions, diffs, or repo state without
  command evidence.
- Do not weaken security defaults, remove tests to make validation pass, or call
  external LLM providers directly from business logic.
- Do not mix tenants or retrieve evidence across tenants.
- Do not log secrets, credentials, tokens, or sensitive payloads.
- Update focused tests for implementation changes.
- Update traceability and worklog after validated changes.

## Product Architecture

- `apps/api`: Python 3.12 FastAPI verification plane.
- `packages/contracts`: TypeScript public contracts and JSON Schemas.
- `packages/sdk`: TypeScript SDK.
- `packages/mcp-server`: JSON-RPC/MCP-compatible server wrapper.
- `apps/console`: Next.js DevEx console.
- `infra`: Docker Compose, security, observability, RAG persistence, and future
  deployment infrastructure.
- `evals`: golden sets, offline scenario runners, metrics, and reports.

Required stack:

- Backend: Python 3.12, FastAPI, Pydantic v2.
- TypeScript surfaces: contracts, SDK, MCP server, Next.js console.
- Data plane targets: PostgreSQL/pgvector or Qdrant, OpenSearch, Redis,
  S3/MinIO.
- Enterprise hardening: OIDC-ready auth, RBAC/ABAC, tenant isolation, audit
  ledger, encryption, Vault-compatible secrets, PII redaction, egress allowlist,
  OpenTelemetry, Prometheus, Grafana, CI gates, evals.

## Core Verification Pipeline

```text
input
  -> extract atomic claims
  -> classify claims
  -> retrieve evidence
  -> verify each claim
  -> detect contradictions
  -> decide action per claim
  -> repair, abstain, block, or allow
  -> produce VerificationRun
  -> write audit ledger
  -> expose trace_id
```

Every final decision must be explainable from claims, evidence, verdicts,
policy version, validator trace, and audit events.

## Verified Platform Baseline

The repository has a real Git history and a tested platform baseline. Current
repository evidence, the traceability matrix, and the latest worklog entry are
authoritative; historical coordination tooling is not part of the product.

Major completed areas recorded in `docs/WORKLOG.md` and
`docs/TRACEABILITY_MATRIX.md`:

- Foundation docs, ADRs, Makefile, CI/security/evals workflow skeleton.
- FastAPI verification plane with trace IDs, structured errors, audit events,
  and OpenAPI export.
- Pydantic, TypeScript, JSON Schema, examples, and OpenAPI contract surfaces for
  core public models and many endpoint wrappers.
- SDK and MCP live API contract tests with trace and tenant propagation.
- Document/RAG retrieval path with tenant filtering, corpus grants, structural
  Markdown chunking, and OpenSearch/pgvector adapter boundaries.
- Tool validation path with pre-tool validation, post-tool validation,
  high-risk approval queue, execution grants, PII/secret redaction, and policy
  explanations.
- Code-agent/sandbox evidence path with command metadata, static file/symbol
  inspection, git diff and changed-symbol evidence, changed-line evidence, and
  stricter proof rules for repository/test/build claims.
- Content security scanning for direct prompt injection, indirect prompt
  injection, and data poisoning markers.
- OPA/Rego policy baseline plus Python policy fallback tests.
- Observability surfaces for OpenTelemetry spans, Prometheus metrics, and
  Grafana dashboard provisioning.
- Evals: smoke scenarios, expanded 21-scenario offline runner, historical
  scenario metrics, and console rendering of eval metrics and trends.
- Security/config gates for auth/RBAC, OIDC smoke wiring, encryption, secrets,
  audit ledger, approvals, corpus grants, backup/retention, RAG persistence,
  dependency audit, npm audit, and container scan configuration.

Do not assume all enterprise runtime integrations are finished. Many current
checks are deterministic local tests, static validators, or dry-run validators.

## Prior Session Context

Read `docs/development/prior-session-report.md` before implementation.
It captures the previous-session report supplied by the user, including the RAG
structural chunking slice, eval scenario history slice, console trend work, and
validation evidence.

Important: the report is historical. Its Git `HEAD` blocker has since been
resolved by the baseline commit. If the prior-session report conflicts with
current repository evidence, report the conflict and trust current evidence.

## Known Local Environment Constraints

- Windows PowerShell host.
- Prefer the standard Makefile gates. If a required tool is unavailable, record
  the exact skipped evidence rather than inferring success.
- Docker and external-service availability vary by session; live claims require
  current command evidence from isolated scratch infrastructure.
- OPA/Rego and other security tools must use the pinned or validated versions
  required by repository gates.

## Scoped Contributor Workflow

A scoped contributor is not the final integrator.

A contributor should:

1. Orient with the required docs and this brief.
2. Inspect current repo state.
3. Work only on the bounded delegated slice.
4. Prefer focused, testable changes over broad abstractions.
5. Run deterministic validation for its slice.
6. Return changed files, validation outcomes, risks, and integration notes.

The integration owner will:

1. Inspect the contributor's actual diff.
2. Integrate or reject changes.
3. Run validation from the main workspace.
4. Update traceability and worklog.
5. Report evidence and next slice.

## Definition Of Done For The Whole Product

The product is not done until it can support enterprise usage across document,
tool, and code-agent hallucination defense with:

- Public contracts synchronized across Pydantic, TypeScript, JSON Schema, and
  OpenAPI.
- Tenant-isolated evidence retrieval and auditability.
- Durable approval, audit, RAG, and policy storage adapters ready for deployment.
- Deterministic sandbox evidence for code-agent claims.
- Safe provider adapter abstraction for OpenAI-compatible APIs, Ollama/local,
  and deterministic mock providers.
- OIDC/RBAC/ABAC integrated with fail-closed production defaults.
- Observability, evals, and security gates in CI.
- Clear console workflows for operational visibility and approvals.
- No accepted requirement without implementation, tests, docs, and recorded
  evidence.

## Near-Term Direction

When no specific task is supplied, prefer read-only orientation or audit first.
Useful next work is usually in one of these tracks:

- Close remaining enterprise runtime gaps that are currently validated only by
  config/static checks.
- Deepen RAG persistence and live service validation.
- Improve semantic verification beyond conservative deterministic matching.
- Expand eval coverage and trend/history storage.
- Harden console workflows for approvals, evals, policy explanations, and audit
  inspection.
- Reduce manual contract synchronization risk.

Pick the smallest vertical slice that advances one track and can be validated
locally without weakening any security or evidence rule.
