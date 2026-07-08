# Plan Master

## Product Goal

Build an enterprise, hybrid, provider-agnostic hallucination defense platform for:

1. LLM responses.
2. Atomic claims inside generated responses.
3. Agent actions before and after tool calls.
4. Code-agent claims about repositories, files, diffs, tests, and builds.

The platform must use real evidence, formal rules, sandbox execution, human approvals, auditability, traceability, and continuous evaluation.

## Product Surfaces

### Documents / RAG

- Extract atomic claims.
- Retrieve evidence.
- Verify claim-by-claim.
- Detect insufficient evidence and contradictions.
- Repair, abstain, block, or allow with citations.

### Agents With Tools

- Validate tool input before execution.
- Classify risk and side effects.
- Require human approval for high-risk actions.
- Validate tool output after execution.
- Sanitize secrets/PII and block unsafe or contradictory output.

### Code Agents

- Verify claims about filesystem, functions, tests, builds, diffs, and commands.
- Execute allowlisted checks in a sandbox.
- Deny network by default.
- Treat stdout, stderr, exit codes, AST/static checks, and diffs as deterministic evidence.

## Mandatory Stack

- Backend: Python 3.12, FastAPI, Pydantic v2, Python workers.
- SDK/MCP/Console: TypeScript, Node, SDK TS, MCP server, Next.js.
- Data: PostgreSQL, pgvector or Qdrant, OpenSearch, Redis, S3/MinIO.
- Infra: Docker, Kubernetes, OpenTelemetry, Prometheus, Grafana.
- Security: OIDC-ready auth, RBAC/ABAC, tenant isolation, audit ledger, encryption, Vault-compatible secrets, PII redaction, egress allowlist.
- Provider abstraction: OpenAI-compatible APIs, Ollama/local, mock provider for tests.

## Public Contracts

Versioned contracts must exist in Pydantic, TypeScript, JSON Schema, and OpenAPI:

- `Claim`
- `Evidence`
- `ClaimVerdict`
- `VerificationRun`
- `ToolCallEnvelope`
- `SandboxRun`

Contract changes must update tests and examples.

## Verification Pipeline

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

Every final decision must be explainable from claims, evidence, verdicts, policy version, validator trace, and audit events.

## Milestones

### M0 Foundation

- Durable repo docs.
- Traceability matrix.
- Monorepo skeleton.
- FastAPI skeleton.
- TypeScript workspace skeleton.
- Docker Compose.
- Makefile.
- CI/security/evals workflow foundation.
- Smoke tests.

### M1 Public Contracts And API Discipline

- Error response model.
- Trace ID on every REST response.
- Audit event on every REST endpoint.
- OpenAPI export gate.
- JSON Schema/Pydantic/TypeScript contract tests.
- Examples of valid and invalid payloads.

### M2 Documents / RAG Vertical Slice

- Document ingestion API for tenant-scoped RAG corpora.
- Structural chunking.
- Hybrid retrieval with metadata, authority, freshness scoring, and persistent
  OpenSearch/pgvector adapter boundaries.
- Contradictory source detection.
- Claim-level verification and repair.

### M3 Tool Validation Vertical Slice

- Pre-tool validation.
- Post-tool validation.
- Approval backend.
- Approval queue UI.
- Policy explanations.

### M4 Code-Agent / Sandbox Vertical Slice

- Sandbox runner.
- Network denied tests.
- Path traversal and destructive command prevention.
- Artifact capture.
- Git diff/static inspection.
- Deterministic evidence for test/build/repo claims.

### M5 Observability, Evals, And Enterprise Hardening

- OpenTelemetry HTTP and domain-stage traces with safe span attributes and local OTLP collector config.
- Prometheus metrics for API HTTP traffic and domain-specific verification, policy, approval, and sandbox decisions; eval metrics remain exported through offline reports.
- Provisioned Grafana dashboard for API and domain safety metrics.
- Golden sets and eval metrics.
- Versioned encryption policy for in-transit and at-rest controls, with CI validation.
- Python and Node dependency audit gates for known vulnerabilities.
- Container image scanning gate for API and console Docker images.
- Provider adapter abstraction for OpenAI-compatible, Ollama/local, and deterministic mock backends.
- OIDC/RBAC/ABAC integration.
- Vault-compatible secret manager integration.
- Versioned backup/restore and retention policy docs with CI validation.
