# Mass QA Acceptance — 2026-07-13

## Decision

Accepted: the repository-wide offline gates and the live capabilities listed
below. Acceptance means the command completed successfully against the current
working tree and its evidence was reviewed. It does not waive requirement-level
risks in the traceability matrix.

## Accepted offline gates

- `make lint`: Ruff and ESLint passed with zero lint errors.
- `make typecheck`: mypy passed 59 Python source files; every TypeScript
  workspace passed type generation/typecheck.
- `make test`: 2,729 Python tests passed with 27 platform/live deselections;
  SDK 17, agent adapters 11, MCP 41, and Console 101 tests passed.
- `make build`, contracts, OpenAPI, policy, eval smoke, and the 21-scenario eval
  suite passed during this campaign.
- `make security-check`: Gitleaks 8.30.1 passed snapshot plus history; secret,
  dependency, encryption, release, auth, OIDC configuration, Vault, audit,
  approval, corpus grant, backup, Helm, RAG, 14-migration, sandbox, container,
  metrics and observability gates passed; both npm audits found 0 vulnerabilities.

## Accepted live capabilities

- Docker sandbox isolation: network denial, immutable source, artifact capture,
  limits and timeout termination.
- PostgreSQL persistence: clean initialization, migrations, tenant isolation,
  audit retry/race exactly-once behavior and approval grant race behavior.
- Hybrid RAG: pgvector plus OpenSearch fusion, tenant isolation, reconciliation,
  template/index validation and cleanup.
- Keycloak API OIDC and browser Console OIDC/BFF: JWT/RBAC/tenant checks,
  state/nonce/PKCE, CSRF/origin boundaries and provider logout.
- Vault secret bootstrap/read checks.
- Observability: OTel JSONL export with ten observed span kinds and leak guard;
  Prometheus target/metrics and Grafana health/datasource checks.
- Redis rate limiting: 32 concurrent requests yielded 7 allowed and 25 blocked,
  with tenant isolation and window expiry.
- S3-compatible encrypted backup/restore: tenant-scoped live drill passed.

## Accepted GitHub PR gates

- Commit `3bb45a548e4288934937f9397ce89710c53e7504` completed GitHub Actions
  `ci` run 29228234027 and `evals` run 29228234026 successfully.
- `security` run 29228234055 completed its main fail-closed gate, both immutable
  third-party image scans, and all ten exact first-party builds plus Trivy
  HIGH/CRITICAL scans successfully. This accepts `SEC-011` for that commit.

## Rejected or pending

- The ingestion worker crash/restart live smoke is not accepted. Its 15 focused
  tests pass, but the Windows execution timed out and a Linux-container replay
  exited before claiming the job. This remains a live defect/investigation.
- Kind/Helm cluster execution, deployed production profile, managed services,
  external OIDC/provider lanes and other authority-dependent checks were not
  executed locally. Static gates for these areas passed, but they remain
  `tested` or pending—not accepted.
