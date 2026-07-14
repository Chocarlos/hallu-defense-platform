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
- Sandbox v3 hardening: canonical Git/index/config/attribute evidence
  (`SBOX-018`), bounded streaming workspace/output with race-aware
  fingerprints and process cleanup (`SBOX-019`), and UID-preconditioned
  foreground Kubernetes cleanup (`SBOX-020`).

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

### M6 Enterprise Runtime Reality

Goal: promote the enterprise capabilities from static-config / local-JSONL evidence to real distributed runtime, delivered as 7 delegable vertical batches. Each batch follows full-slice discipline (implementation + focused tests with injected fakes + docs + TRACEABILITY_MATRIX rows + WORKLOG entry + validation evidence). Items advance to `accepted` only through a recorded QA decision backed by current deterministic evidence.

- B1 PostgreSQL core: shared pool (services/postgres.py, SqlConnectionProvider / PooledPostgresProvider over psycopg-pool), Postgres audit ledger (bounded export, no replay-all) and approval queue (decide-once / consume-once via WHERE+RETURNING), repeatable migrations (schema_migrations + idempotent applier). New PY-018/019/020.
- B2 Live CI lane + Keycloak OIDC: .github/workflows/live.yml (dispatch + push master + weekly cron), Keycloak service with committed realm export, client_credentials + --api OIDC smokes. New SEC-014, CI-022.
- B3 Sandbox Docker isolation: SandboxExecutionBackend abstraction (host extraction + DockerContainerBackend), sandbox.Dockerfile non-root, isolation-flag gate. New SBOX-016/017, CI-023.
- B4 Live observability + scrape auth: OTEL file-sink export assertion, Prometheus/Grafana live smokes, authenticated /metrics (constant-time bearer via SecretManager). New OBS-004/005/006, CI-024.
- B5 Evals runtime: versioned enforced thresholds with anti-weakening floor, reproducible verifier calibration + drift gate, eval publish/list persistence + Prometheus gauges. New EVAL-003/004/005, API-022/023, CTR-026, CI-025/026.
- B6 Durable ingestion worker: PostgreSQL outbox (FOR UPDATE SKIP LOCKED), async mode (default sync unchanged), idempotent backfill/reindex. New RAG-008/009, API-024, CTR-027, CI-027.
- B7 Production profile + backup/restore + K8s: docker-compose.prod.yml overlay (fail-closed), Vault + MinIO wired, real retention/backup/restore drill + tenant deletion, Helm chart validated on kind. New FND-013/014, SEC-015/016, CI-028/029.

Confirmed scope decisions (Carlos): sandbox = Docker container per run; live OIDC = local Keycloak in Compose; production = Compose prod-profile first, K8s/Helm (kind) last; calibration = versioned thresholds that block CI + reproducible confidence curves. Execution: each batch delegated as a bounded assignment; diff inspected and revalidated from master before integration. Detailed assignments: docs/development/fable-enterprise-batch-2.md.

### M7 Public Launch Layer (WIP)

Goal: add a bilingual public entry point and a privacy-preserving demo-request
boundary without extending earlier QA acceptance to unverified launch code. The
implementation checkpoint is `fb111c1e15c87e40006844d62e37616a84ab796f`;
promotion requires current evidence from the exact candidate commit.

- TS-011: bilingual landing and privacy routes at `/`, `/en`, `/privacy`, and
  `/en/privacy`; preserved authenticated Console at `/console`; localized
  metadata/social card; responsive, keyboard, accessibility, reduced-motion,
  and Web Vitals evidence at the required browser/viewport matrix.
- SEC-020: disabled-by-default `/demo-request` intake with a versioned public
  request/response contract, minimization and consent, no sensitive logging,
  Redis-backed rate limiting/idempotency, generic failures, honeypot behavior,
  webhook delivery, metrics, and fail-closed production configuration.
- CI-033: deterministic Vitest and Playwright launch gates, BrowserStack
  compatibility execution, production build checks, and CI wiring that cannot
  turn missing credentials or unexecuted browsers into compatibility evidence.

Audit decision for this checkpoint: TS-011, SEC-020, and CI-033 are
`implemented`, not `accepted`. The current marketing Playwright run is red,
BrowserStack and real Redis/webhook execution are absent, 320 px horizontal
overflow and the keyboard-tour regression remain reproducible, no LCP/INP/CLS
budget is enforced, and the Kind Console smoke still probes `/` instead of
exercising an authenticated `/console` flow. The traceability matrix and
worklog record the exact evidence and remaining blockers.
