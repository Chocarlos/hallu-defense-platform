# Worklog

## 2026-07-08 - OpenAPI drift gate

Slice selected:

- Closed the `CI-005` gap by adding an executable drift check for the committed
  OpenAPI artifact.

Implementation:

- Refactored `scripts/ci/export_openapi.py` so schema construction and
  deterministic rendering can be reused by checks and tests.
- Added `scripts/ci/check_openapi.py`, which regenerates OpenAPI in memory,
  compares it against `docs/api/openapi.yaml`, and fails with a unified diff if
  the committed artifact is stale.
- Added focused tests in `apps/api/tests/test_openapi_ci.py` proving generated
  artifacts pass and stale artifacts fail.
- Added `openapi-check` to `Makefile`.
- Wired `python scripts/ci/check_openapi.py` into the backend CI job after API
  tests.
- Updated `docs/api/README.md` and `docs/TRACEABILITY_MATRIX.md` for the new
  gate.

Validation:

- `.venv\Scripts\python scripts\ci\check_openapi.py`: OpenAPI artifact is up
  to date.
- `.venv\Scripts\python -m pytest apps\api\tests\test_openapi_ci.py -q`: 2
  passed.
- `.venv\Scripts\python -m ruff check scripts\ci\export_openapi.py scripts\ci\check_openapi.py apps\api\tests\test_openapi_ci.py`:
  all checks passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py` followed by
  `git diff --exit-code -- docs\api\openapi.yaml`: no generated artifact diff.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 270 passed, 1
  FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: no whitespace errors; Windows CRLF warnings only.

Remaining risks:

- The gate detects generated artifact drift. It does not yet classify semantic
  API compatibility or breaking changes between released contract versions.

## 2026-07-08 - Fable persistent branch alignment refresh

Slice selected:

- Refreshed the operational evidence for the Fable delegation branch before
  concurrent Codex/Fable development.

Implementation:

- Verified `master` and `fable5/delegation` both point to
  `4ac9df52d37c5999c6aaae7c567c124e51b9a026`.
- Updated `docs/development/fable-delegation.md` so its current evidence no
  longer treats the initial baseline commit as the latest delegation state.
- Updated `docs/development/fable-project-brief.md` with the latest Fable
  context-validation commit.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-012` with the aligned branch
  and worktree evidence.
- Launched Fable workflow `wf_466d0d6a-cb2` in write mode for a bounded RAG
  persistence tenant-isolation hardening slice while Codex stayed on `master`.

Validation:

- `git status --short --branch`: clean `master` before this documentation
  refresh.
- `git -C .claude\worktrees\fable5-delegation status --short --branch`: clean
  `fable5/delegation`.
- `git rev-parse --verify HEAD` and
  `git rev-parse --verify fable5/delegation`: both resolved
  `4ac9df52d37c5999c6aaae7c567c124e51b9a026`.
- `git diff --name-status master...fable5/delegation`: no differences before
  the new Fable workflow launch.

Remaining risks:

- Fable workflow `wf_466d0d6a-cb2` is still running at the time this entry was
  written; its diff must be inspected and validated before integration.
- The saved workflow uses temporary worktree isolation. The persistent
  `fable5/delegation` branch remains the durable coordination branch and must
  be fast-forwarded after accepted integration work.

## 2026-07-08 - Fable project context package

Slice selected:

- Added the durable context package Fable must read before any implementation
  delegation.

Implementation:

- Added `docs/development/fable-project-brief.md` with the product mission,
  architecture, prior Codex work, current state, operating rules, end-state
  definition, and near-term direction.
- Added `docs/development/fable-prior-session-report.md` preserving the
  user-supplied previous-session report, including RAG structural chunking,
  eval history/console work, validation evidence, and the earlier Fable/Git
  blocker.
- Updated `.claude/workflows/fable-delegate.js` so write mode requires
  `goal` and `acceptance`, injects the project brief plus prior-session report,
  and returns `projectBriefRead`, `priorSessionReportRead`, and
  `acceptanceMet`.
- Updated `.claude/agents/fable-platform-engineer.md` and
  `docs/development/fable-delegation.md` so the context docs are part of the
  required orientation.
- Committed the context package as
  `4da8223 chore: add fable project context package` and fast-forwarded the
  persistent `fable5/delegation` worktree to that commit.

Validation:

- `node --check .claude\workflows\fable-delegate.js`: passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: no whitespace errors; Windows CRLF warnings only.
- Claude Code workflow probe `wf_e4e6e96f-aa3` returned `success=true`,
  `projectBriefRead=true`, `priorSessionReportRead=true`,
  `acceptanceMet=true`, `HEAD=4da8223`, and `changedFiles=[]`.
- `git -C .claude\worktrees\fable5-delegation log --oneline -1`: confirmed
  the persistent Fable worktree was at `4da8223` before this worklog update.

Remaining risks:

- Direct `mcp__claude_code.Agent` still has no registered local agent types in
  this session.
- Fable workflow worktrees do not include `.venv` or `node_modules`; first
  write-mode tasks must either bootstrap dependencies in the worktree or return
  a diff for Codex to validate from the main workspace.
- No Fable-generated product diff has been integrated yet; the first write-mode
  task should be small and additive.

## 2026-07-08 - Claude Fable delegation path repaired

Slice selected:

- Focused only on making Claude Fable 5 usable as a delegated teammate for
  future project work.

Diagnosis:

- The repository had no valid `HEAD`, so git worktree isolation could not work.
- `.claude-fable-work/` was not ignored and could have been accidentally added
  to the product repository.
- Direct `mcp__claude_code.Agent` launch with
  `subagent_type=fable-platform-engineer` still fails in this session because
  the Claude Code MCP reports no registered local agent types.
- The Claude Code `Workflow` path can launch real `claude-fable-5` subagents.

Implementation:

- Updated `.gitignore` so `.claude-fable-work/`, `.claude/worktrees/`, and
  `.claude/settings.local.json` are excluded from product commits.
- Created the initial repository baseline commit:
  `8dec1b3 chore: establish repository baseline`.
- Created persistent Fable branch/worktree:
  `fable5/delegation` at `.claude/worktrees/fable5-delegation`.
- Added reusable workflow `.claude/workflows/fable-delegate.js`, which delegates
  one scoped task to Fable with `model: "fable"` and git worktree isolation.
- Added `docs/development/fable-delegation.md` with the operating procedure,
  isolation rules, evidence, and integration protocol.
- Updated `docs/TRACEABILITY_MATRIX.md` with `FND-012`.

Validation:

- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found
  before creating the baseline commit.
- `git diff --check`: passed before the baseline commit.
- `git rev-parse --verify HEAD`: resolved
  `8dec1b3b4c63ba65fad7a9664da68e88bbbc644a` after the commit.
- Inline Claude Code workflow probe `wf_55d0feb2-b18`: returned
  `model=claude-fable-5`, `headResolves=true`, `shortHead=8dec1b3`,
  `agentsMdVisible=true`, and clean isolated worktree.
- `git worktree add -b fable5/delegation .claude\worktrees\fable5-delegation HEAD`:
  created the persistent delegation worktree.
- `git -C .claude\worktrees\fable5-delegation status --short --branch`:
  reported `## fable5/delegation`.
- `node --check .claude\workflows\fable-delegate.js`: passed.
- Saved workflow probe `wf_6874c64f-008`: returned `success=true`,
  `mode=read`, `HEAD=8dec1b3`, `AGENTS.md` and required docs visible, clean
  isolated worktree, and no changed files.

Remaining risks:

- Direct `mcp__claude_code.Agent` remains unavailable for named local agents in
  this MCP session; use `mcp__claude_code.Workflow` and the saved
  `.claude/workflows/fable-delegate.js` route for Fable delegation.
- Future Fable write-mode output must still be inspected, validated, and
  integrated by Codex before product claims are made.

## 2026-07-08 - RAG OpenSearch tenant-scoped document IDs

Slice selected:

- Continued the RAG persistence hardening path by removing a shared-index
  overwrite risk in the OpenSearch adapter.

Implementation:

- Changed OpenSearch bulk indexing so the physical `_id` is derived from
  `tenant_id` plus public `evidence_id` instead of using bare `evidence_id`.
- Preserved the public `evidence_id` field in `_source`, so evidence contracts
  and downstream claim maps remain stable.
- Added a focused regression test proving two tenants can index the same
  public `evidence_id` without producing the same OpenSearch document `_id`.
- Updated traceability for `API-003` and `RAG-002`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py -q`:
  29 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\rag_index.py apps\api\tests\test_rag_index_adapters.py`:
  all checks passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 268 passed, 1
  FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.

Remaining risks:

- This verifies request construction and adapter behavior with deterministic
  fakes. Live OpenSearch and pgvector services were not started on this host.
- Tenant-scoped physical IDs prevent shared-index overwrites; broader live
  persistence and deployment validation remain tracked under `CI-012`.

## 2026-07-08 - M5 eval scenario history and console trends

Slice selected:

- Closed the previous eval-dashboard gap by persisting recent expanded scenario
  eval runs and rendering latest-vs-previous trends in the console.

Coordination:

- Direct `mcp__claude_code.Agent` launch with `model=fable` failed because the
  Claude Code session reported no registered agent types.
- Claude workflow launch with `model=fable` and worktree isolation failed
  because the initialized repository has no valid `HEAD` yet.
- A filesystem-isolated copy was created at
  `.claude-fable-work/scenario-history` and Fable launched there as
  `claude-fable-5`. The subagent remained blocked by Claude Code command
  approval restrictions and did not produce an integrable product diff during
  this cycle, so the history slice was implemented locally and verified before
  integration.

Implementation:

- `evals/runners/scenarios.py` now appends bounded recent run metrics to
  `evals/reports/scenario-history.json` when `write_report=True`.
- Added public contracts, JSON Schemas, and valid/invalid examples for:
  - `EvalScenarioHistoryEntry`,
  - `EvalScenarioHistoryReport`.
- Extended the console eval report loader to find, load, and validate
  `evals/reports/scenario-history.json`.
- Extended the console `Eval scenarios` panel with latest pass rate, latest p95
  latency, deltas versus the previous run when available, and recent run rows.
- Added parser tests for the real history artifact and malformed/duplicate
  history payloads.
- Updated `docs/schemas/README.md` and traceability for `CTR-022`, `TS-009`,
  `EVAL-002`, `CI-003`, `CI-004`, and `CI-006`.

Validation:

- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 21 scenarios,
  wrote `evals/reports/scenario-metrics.json`, and appended
  `evals/reports/scenario-history.json`; pass rate 1.0, p95 latency 4.795 ms.
- `.venv\Scripts\python -m pytest apps\api\tests\test_eval_scenarios.py -q`:
  3 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check evals\runners\scenarios.py apps\api\tests\test_eval_scenarios.py`:
  all checks passed.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 55 JSON
  schema files, 55 valid examples, 55 invalid examples, and 55 TypeScript
  interfaces.
- `npm --workspace @hallu-defense/console run test`: 6 console eval-report
  tests passed.
- `npm --workspace @hallu-defense/console run typecheck`: `next typegen` and
  `tsc --noEmit` passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 267 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.
- `npm run typecheck`: all TypeScript workspaces passed.
- `npm run test`: SDK 7 tests passed, agent-adapters 5 tests passed, MCP
  server 6 tests passed, and console 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and console
  production build passed; Next.js prerendered `/` and `/_not-found`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.
- `Invoke-WebRequest http://127.0.0.1:3000`: returned HTTP 200 and rendered
  HTML contained `Eval scenarios` and `latest pass`.

Remaining risks:

- Eval trend storage is still an offline JSON artifact, not a live metrics API
  or database-backed time series.
- Fable's isolated copy remains auxiliary work only; no Fable diff was merged
  because no completed, verified product diff was available.

## 2026-07-08 - RAG structural section chunking

Slice selected:

- Advanced `RAG-002` with a conservative structural chunker for Markdown-style
  documents, separate from the eval/history work delegated to Fable.

Coordination:

- Direct Claude Code agent launch with `model=fable` failed because the session
  reported no registered agent types (`general-purpose` unavailable).
- Claude workflow launch with `model=fable` and worktree isolation failed
  because the repository has no valid `HEAD`; `git rev-parse HEAD` fails in
  this initialized-but-uncommitted repo.
- Created a filesystem-isolated copy at
  `.claude-fable-work/scenario-history` excluding `.git`, `.venv`,
  `node_modules`, caches, and prior agent work, then relaunched a Fable
  workflow against that copy for the eval scenario-history slice.

Implementation:

- Kept plain-text paragraph chunking behavior unchanged for documents without
  Markdown headings.
- Added heading-aware section chunking in `HybridRetriever` for Markdown
  headings `#` through `######`.
- Added per-chunk section heading, section path, section level, and chunk kind
  metadata for persistent RAG indexing.
- Added readable `structured_content.structure` for local evidence and
  reconstruction of the same shape when evidence is loaded from OpenSearch or
  pgvector metadata.
- Added tests for persistent indexing metadata, inline retrieval structure, and
  OpenSearch structure reconstruction.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py -q`:
  28 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\retrieval.py apps\api\src\hallu_defense\services\rag_index.py apps\api\tests\test_rag_index_adapters.py`:
  all checks passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 266 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.
- `git diff --check`: passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets
  found.
- `npm run typecheck`: all TypeScript workspaces passed, including Next
  route type generation and `tsc --noEmit`.
- `npm run test`: SDK 7 tests passed, agent-adapters 5 tests passed, MCP
  server 6 tests passed, and console eval-report 4 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and console
  production build passed; Next.js prerendered `/` and `/_not-found`.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 53 JSON
  schema files, 53 valid examples, 53 invalid examples, and 53 TypeScript
  interfaces.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and
  wrote `evals/reports/smoke-metrics.json`; p95 latency 57.521 ms.
- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 21 scenarios
  and wrote `evals/reports/scenario-metrics.json`; pass rate 1.0 and p95
  latency 4.574 ms.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 29 selected Python
  policy/config tests passed; local `opa` binary was unavailable, so static
  Rego checks ran and passed for 2 files.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`:
  validated RAG persistence configuration.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- Structural parsing is intentionally limited to Markdown-style headings and
  paragraphs. HTML/PDF/table-aware structural parsing remains future work.
- Fable's eval-history workflow is running in a filesystem copy and still needs
  review before any integration into the main workspace.

## 2026-07-07 - Initial vertical slice before expanded objective

Implemented:

- FastAPI verification plane.
- Pydantic contracts.
- TypeScript contracts, SDK, and MCP JSON-RPC server.
- Next.js DevEx console.
- Docker Compose and CI.
- Initial unit and SDK tests.

Validation observed:

- `pytest apps/api/tests`: 5 passed.
- `ruff check apps/api/src apps/api/tests`: passed.
- `npm run typecheck`: passed.
- `npm run test`: SDK tests passed.
- `npm run build`: passed.
- `npm audit --omit dev`: 0 vulnerabilities after pinning Next canary with fixed PostCSS.
- API smoke test against `/verification/run`: returned `trace_id` and `final_decision`.

## 2026-07-07 - Foundation scope alignment

Input:

- Read pasted objective from Codex attachment.
- Read existing repo state.
- Confirmed root `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md` were missing.

Changes in progress:

- Added durable project documents.
- Added requirement traceability matrix.
- Added standard task runner.
- Added CI/security/evals support scripts.

Validation for this cycle:

- First validation attempt found two issues:
  - `pytest apps/api/tests` failed because `test_contracts.py` resolved the repository root one level too high.
  - `evals/runners/smoke.py` expected `repaired` for an insufficient-evidence case where the correct current decision is `abstained` because no supported claim remains.
- Fixes applied:
  - Corrected `ROOT = Path(__file__).resolve().parents[3]` in `apps/api/tests/test_contracts.py`.
  - Updated `evals/golden_sets/smoke.json` to expect `abstained` for the insufficient-evidence scenario.
- Second validation attempt found a Next canary type generation issue:
  - `npm run typecheck` failed because `.next/types` references are generated by Next and can be absent before type generation.
- Fix applied:
  - Updated console `typecheck` script to run `next typegen` before `tsc`.

Validation after fixes:

- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 20 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 8 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 3 JSON schema files.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed after `next typegen`.
- `npm run test`: SDK tests passed, 2 tests.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Runner note:

- `make`, `mingw32-make`, and `nmake` were not available on this host, so the Makefile was not executed directly. Equivalent commands were run and recorded above.

## 2026-07-08 - API discipline: trace, errors, audit events

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected M1 API discipline slice because the matrix showed API-012 and API-013 as `not_started`, and API-011 lacked an error model.

Implemented:

- Added `ErrorResponse`, `AuditEvent`, and `AuditExportResponse` Pydantic contracts.
- Added request trace context and trace ID generation.
- Added FastAPI middleware that:
  - Accepts valid incoming `x-trace-id` or generates one.
  - Adds `x-trace-id` to every response.
  - Writes an in-memory `AuditEvent` for every HTTP request.
- Added structured exception handlers for HTTP errors, validation errors, and unexpected errors.
- Changed `/audit/export` to return `{ trace_id, runs, events }`.
- Added TypeScript contracts for error/audit export.
- Added SDK methods `repairResponse()` and `exportAudit()`.
- Added contract tests for OpenAPI error responses, trace headers, audit events, HTTP errors, and validation errors.

Validation issues found and fixed:

- Initial Python validation failed because `ErrorResponse` was inserted outside the intended import lists in `routes.py` and `domain/__init__.py`; fixed imports.
- Mypy then rejected FastAPI/Starlette handler typing and router response typing; fixed handler signatures and typed `ERROR_RESPONSES` as FastAPI expects.
- Removed a leftover `status` reference after switching response codes to literals.

Validation after fixes:

- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 11 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 3 JSON schema files.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: 3 SDK tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- Audit ledger is in-memory, not persistent append-only storage.
- Trace ID is guaranteed in headers for all endpoints; only some bodies include trace_id.
- New `ErrorResponse`, `AuditEvent`, and `AuditExportResponse` contracts do not yet have JSON Schema files.
- OpenTelemetry integration is still pending.

## 2026-07-08 - Contract schemas and executable examples

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M1 contract slice because the matrix showed missing JSON Schemas and examples for `VerificationRun`, `ToolCallEnvelope`, `SandboxRun`, `ErrorResponse`, `AuditEvent`, and `AuditExportResponse`.

Implemented:

- Added JSON Schemas for:
  - `VerificationRun`
  - `ToolCallEnvelope`
  - `SandboxRun`
  - `ErrorResponse`
  - `AuditEvent`
  - `AuditExportResponse`
- Tightened existing `Claim`, `Evidence`, and `ClaimVerdict` schemas to require the full public field set.
- Added valid and invalid example payloads for all 9 public schema files.
- Upgraded `scripts/ci/check_json_schemas.py` to:
  - validate schemas with JSON Schema Draft 2020-12,
  - resolve `$ref` across local schema files,
  - verify all valid examples pass,
  - verify all invalid examples fail.
- Added contract tests that enforce required schema coverage and example behavior.
- Added `jsonschema` as a Python dev dependency because schema/example validation needs a standards-compliant Draft 2020-12 validator.

Validation after fixes:

- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 9 JSON schema files, 9 valid examples, and 9 invalid examples.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 12 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: 3 SDK tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- Endpoint-specific request/response schemas beyond the named public contracts are not yet all standalone JSON Schema files.
- Pydantic models still allow some defaulted fields that the public JSON Schemas require for emitted/recorded contract objects.
- JSON Schema and TypeScript are still manually synchronized; code generation is pending.

## 2026-07-08 - Live SDK/API and MCP/API contract tests

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M1 integration slice because the matrix showed SDK live contract tests and MCP trace/tenant contract tests as missing.

Implemented:

- Added optional `traceId` support to `HalluDefenseClient`; the SDK now sends `x-trace-id` when provided.
- Improved SDK structured error extraction to prefer API `message` before legacy `detail`.
- Changed `VerificationRunRequest.tenant_id` to optional so `/verification/run` can use `x-tenant-id` when the body omits tenant context.
- Added an orchestrator fallback to `local-dev` for direct service calls outside FastAPI.
- Added Python contract coverage that verifies `/verification/run` uses the tenant header when the request body omits `tenant_id`.
- Hardened the MCP server:
  - per-call trace IDs,
  - runtime argument object/type validation,
  - unsupported top-level field rejection,
  - `trace_id` in tool `structuredContent`,
  - env/header-based tenant context via `HALLU_DEFENSE_TENANT_ID`.
- Added live SDK/API contract tests that start FastAPI with Uvicorn and verify trace, tenant, claims/verdicts, and audit events.
- Added live MCP/API contract tests that talk JSON-RPC over stdin/stdout, verify required tools, trace propagation, tenant propagation, audit events, and rejection of a cross-tenant `tenant_id` argument.
- Updated TypeScript CI to install the Python API before TypeScript tests.
- Updated the MCP package test script to build the SDK first because runtime imports resolve to the SDK workspace `dist`.

Validation issues found and fixed:

- Initial `npm run test` failed in MCP contract tests because the MCP server imported a stale SDK `dist` that did not yet send `x-trace-id`.
  - Fix: changed the MCP test script to run `npm --workspace @hallu-defense/sdk run build` before Vitest.
- Initial `mypy` failed because `VerificationRunRequest.tenant_id` is now `str | None` while `VerificationRun.tenant_id` remains required.
  - Fix: added a service-level `request.tenant_id or "local-dev"` fallback in the orchestrator.

Validation after fixes:

- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 13 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 9 JSON schema files, 9 valid examples, and 9 invalid examples.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: SDK 4 tests passed, MCP 3 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- MCP runtime validation is top-level/type-minimum validation, not full JSON Schema validation of nested Claim/Evidence payloads.
- Tenant context is env/header-based; auth-derived tenant identity and RBAC/ABAC are still pending.
- Live contract tests use in-memory services and Uvicorn, not deployed Docker/Kubernetes infrastructure.
- Audit ledger remains in-memory.

## 2026-07-08 - MCP runtime JSON Schema validation and all-tool contract coverage

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next MCP contract slice because the matrix showed remaining risk around deep MCP validation and only `repair_response` had live end-to-end coverage.

Implemented:

- Added `ajv` and `ajv-formats` to `@hallu-defense/mcp-server`.
  - Justification: the MCP boundary must execute the existing Draft 2020-12 public JSON Schemas at runtime, including `date-time` formats in Evidence freshness.
- Added `packages/mcp-server/src/schema-validation.ts`, which loads public JSON Schemas from `packages/contracts/schemas` and exposes typed `validateContract()` / `validateContractArray()` helpers.
- Wired JSON Schema validation into MCP inputs for:
  - `Claim` arrays,
  - `Evidence` arrays,
  - `ToolCallEnvelope`.
- Wired output validation before returning MCP `structuredContent` for:
  - `ClaimVerdict`,
  - retrieved `Evidence`,
  - `SandboxRun`,
  - `VerificationRun`.
- Added conservative manual validation for `DocumentInput`, which is currently request-only and does not yet have a standalone public JSON Schema.
- Expanded live MCP/API tests:
  - `verify_claims`
  - `retrieve_evidence`
  - `validate_tool_call`
  - `validate_tool_output`
  - `run_repo_checks`
  - `explain_policy`
  - `repair_response`
- Added a negative MCP test proving an invalid nested `Claim` is rejected by schema validation before proxying to FastAPI.

Validation issues found and fixed:

- Initial MCP typecheck failed because Ajv's ESM/CJS typings exposed the wrong default constructor under NodeNext.
  - Fix: imported named `Ajv2020`.
- Initial MCP typecheck then failed because `ajv-formats` CJS typings were not callable under NodeNext default import.
  - Fix: loaded `ajv-formats` through `createRequire()` and typed the plugin at the boundary.

Validation after fixes:

- `npm --workspace @hallu-defense/mcp-server run typecheck`: passed.
- `npm --workspace @hallu-defense/mcp-server run test`: 5 MCP tests passed.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 13 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 9 JSON schema files, 9 valid examples, and 9 invalid examples.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: SDK 4 tests passed, MCP 5 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- `DocumentInput`, `RepoChecksRunRequest`, `ToolValidationResponse`, and `PolicyEvaluationResponse` still need standalone JSON Schemas if they are to be validated by shared public contracts instead of local/manual validation.
- Tenant context remains env/header-based rather than OIDC/RBAC-derived.
- Audit ledger remains in-memory.

## 2026-07-08 - Tool boundary request/response JSON Schemas

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next contracts slice because the previous cycle left `DocumentInput`, `RepoChecksRunRequest`, `ToolValidationResponse`, and `PolicyEvaluationResponse` without standalone JSON Schemas.

Implemented:

- Added standalone JSON Schemas and valid/invalid examples for:
  - `DocumentInput`
  - `EvidenceRetrievalResponse`
  - `PolicyEvaluationRequest`
  - `PolicyEvaluationResponse`
  - `RepoChecksRunRequest`
  - `ToolValidationResponse`
  - `VerificationRunRequest`
- Updated Python contract tests so the new schema names are required.
- Updated `docs/schemas/README.md` to list the expanded contract set.
- Extended MCP runtime schema loading to include the new contracts.
- Replaced MCP manual validation with shared JSON Schema validation for:
  - document inputs,
  - repo check requests,
  - policy requests,
  - verification run requests,
  - retrieval responses,
  - tool validation responses,
  - policy evaluation responses.
- Added MCP negative tests proving invalid request-only contracts are rejected before proxying:
  - empty `commands` for `run_repo_checks`,
  - missing `action` for `explain_policy`.

Validation issues found and fixed:

- First schema validation failed because `invalid/evidence-retrieval-response.json` still passed.
  - Fix: changed the invalid example to include an unsupported `authority`, making the negative case deterministic.

Validation after fixes:

- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 16 JSON schema files, 16 valid examples, and 16 invalid examples.
- `npm --workspace @hallu-defense/mcp-server run typecheck`: passed.
- `npm --workspace @hallu-defense/mcp-server run test`: 6 MCP tests passed.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 13 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: SDK 4 tests passed, MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- Non-tool endpoint-specific schemas are still incomplete, especially claim extraction/classification/repair request-response wrappers.
- Public JSON Schemas and TypeScript types are still manually synchronized; code generation remains pending.
- Tenant context remains env/header-based rather than OIDC/RBAC-derived.
- Audit ledger remains in-memory.

## 2026-07-08 - Endpoint wrapper schemas and TypeScript coverage gate

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next contract slice because non-tool endpoint wrappers and TS/schema sync checks were still incomplete.

Implemented:

- Added TypeScript contract interfaces for:
  - `ClaimExtractionRequest`
  - `ClaimExtractionResponse`
  - `ClaimClassificationRequest`
  - `ClaimClassificationResponse`
  - `EvidenceRetrievalRequest`
  - `ClaimVerificationRequest`
  - `ClaimVerificationResponse`
- Added JSON Schemas and valid/invalid examples for:
  - `SourceSpan`
  - `Freshness`
  - `ClaimExtractionRequest`
  - `ClaimExtractionResponse`
  - `ClaimClassificationRequest`
  - `ClaimClassificationResponse`
  - `EvidenceRetrievalRequest`
  - `ClaimVerificationRequest`
  - `ClaimVerificationResponse`
  - `ResponseRepairRequest`
  - `ResponseRepairResponse`
  - `AuditExportRequest`
- Extended `scripts/ci/check_json_schemas.py` to parse exported TypeScript interfaces and require a matching JSON Schema.
  - `ClaimVerdict` maps intentionally to existing `verdict.schema.json`.
- Updated Python contract tests to require the expanded schema set.
- Updated `docs/schemas/README.md` with the full schema inventory.

Validation after fixes:

- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 28 JSON schema files, 28 valid examples, 28 invalid examples, and 28 TypeScript interfaces.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 13 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: SDK 4 tests passed, MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- The new TS/schema coverage gate proves naming coverage and executable examples, not full semantic equivalence of every property.
- JSON Schema and TypeScript are still manually synchronized; code generation remains pending.
- Endpoint behavior tests still need to expand beyond contract shape into richer extraction/classification/repair semantics.
- Tenant context remains env/header-based rather than OIDC/RBAC-derived.
- Audit ledger remains in-memory.

## 2026-07-08 - M2 RAG local hybrid filtering, scoring, and source contradictions

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M2 RAG slice because the matrix showed metadata filtering, tested authority/freshness scoring, and multi-source contradiction detection as gaps.

Implemented:

- Added optional `metadata_filter` to `EvidenceRetrievalRequest` in Pydantic, TypeScript, JSON Schema, examples, SDK, and MCP validation.
- Upgraded the local `HybridRetriever` to:
  - apply exact/list-aware metadata filtering,
  - preserve ranked evidence order while deduplicating selected chunks,
  - compute deterministic BM25-style lexical score, vector-style token similarity, authority score, freshness score, and total score,
  - expose retrieval score traces in `Evidence.structured_content.retrieval`,
  - derive evidence freshness from document metadata where available.
- Added multi-source numeric contradiction detection in `ClaimVerifier` so relevant supporting and conflicting evidence returns `CONTRADICTED` instead of arbitrarily trusting the strongest source.
- Updated MCP retrieval validation to use the full `evidence-retrieval-request` JSON Schema.
- Updated traceability and schema docs for the new retrieval request field and M2 evidence.

Validation issues found and fixed:

- Initial mypy run rejected converting `dict[str, object]` score fields with `float(...)`.
  - Fix: added explicit numeric narrowing for score fields before ranking.
- Initial MCP typecheck rejected `exactOptionalPropertyTypes` usage and lacked `evidence-retrieval-request` in the MCP schema registry.
  - Fix: constructed retrieval options only with defined fields and added the request schema to `ContractSchemaName`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 8 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 23 source files.
- `npm --workspace @hallu-defense/mcp-server run typecheck`: passed.
- `npm --workspace @hallu-defense/sdk run typecheck`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 28 schemas, 28 valid examples, 28 invalid examples, and 28 TypeScript interfaces.
- `npm --workspace @hallu-defense/mcp-server run test`: 6 MCP tests passed.
- `npm --workspace @hallu-defense/sdk run test`: SDK 4 tests passed.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m pytest apps/api/tests`: 16 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote updated `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: SDK 4 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- Retrieval is still a local deterministic scorer, not OpenSearch BM25 plus pgvector/Qdrant integration.
- Metadata filters are tested for inline documents; persistent corpus tenant filters remain pending.
- Contradiction detection covers numeric conflicts deterministically, not full semantic contradiction/NLI.

## 2026-07-08 - M3 approval backend and DevEx queue

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the M3 approvals slice because high-risk tool calls already returned `require_human_review`, but no approval backend existed.

Implemented:

- Added approval workflow contracts in Pydantic, TypeScript, JSON Schema, and examples:
  - `ApprovalRecord`
  - `ApprovalListRequest`
  - `ApprovalListResponse`
  - `ApprovalDecisionRequest`
  - `ApprovalDecisionResponse`
- Extended `ToolValidationResponse` with optional `approval_id`.
- Added `ApprovalQueue`, an in-memory tenant-aware approval ledger that:
  - creates pending approvals,
  - lists approvals by tenant/status/trace,
  - approves or rejects once,
  - blocks cross-tenant decisions,
  - redacts sensitive keys in tool input and caller context before storage.
- Changed `/tools/validate-input` so high-risk or explicitly approval-required tool calls create a pending approval and return `approval_id`.
- Added REST endpoints:
  - `POST /approvals/list`
  - `POST /approvals/decide`
- Added SDK methods:
  - `listApprovals()`
  - `decideApproval()`
- Added a console approval panel that lists pending approvals, enqueues a high-risk tool validation through the typed SDK, and can approve/reject approvals.
- Updated OpenAPI, schema docs, traceability matrix, and worklog.

Validation issues found and fixed:

- `next dev` could not start a second dev server because an existing console dev process was already running on port `3000`.
  - Fix: left the existing process untouched and started a production console server on port `3010` pointing to the verified API on port `8010`.
- Initial attempt to start console with an inline PowerShell env assignment expanded incorrectly.
  - Fix: started the console with inherited `NEXT_PUBLIC_API_BASE_URL` environment instead.
- Secret scan flagged the console demo payload because it used a long value beside `api_key`.
  - Fix: changed the demo value to a short non-secret placeholder while keeping the sensitive key name so backend redaction is still exercised.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 9 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `npm --workspace @hallu-defense/sdk run typecheck`: passed.
- `npm --workspace @hallu-defense/sdk run test`: 5 SDK tests passed.
- `npm run typecheck`: passed.
- `npm --workspace @hallu-defense/console run build`: passed.
- `.venv\Scripts\python -m pytest apps/api/tests`: 17 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote updated `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- Final post-fix checks after the console demo value change:
  - `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
  - `npm --workspace @hallu-defense/console run build`: passed.

Manual runtime checks:

- API health at `http://127.0.0.1:8010/health`: returned `{"status":"ok","environment":"local"}`.
- Console at `http://127.0.0.1:3010`: returned HTTP 200.
- `POST /tools/validate-input` against `8010` created `approval_id` for a high-risk tool call.
- `POST /approvals/list` returned the pending approval with `api_key` and `token` redacted.
- `POST /approvals/decide` approved the pending approval and returned status `approved`.

Remaining risks:

- Approval queue is in-memory and not persistent/append-only yet.
- Human identity is caller-supplied until OIDC/RBAC/ABAC is implemented.
- High-risk execution is still blocked and queued, but there is no approval token handoff for a later executor yet.
- Console approval panel has build/typecheck/runtime smoke evidence, not browser interaction/e2e tests.

## 2026-07-08 - M4 sandbox command policy, network deny, secrets, and artifacts

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the M4 sandbox hardening slice because the matrix showed network denial, destructive command tests, and artifact capture as incomplete.

Implemented:

- Hardened `SandboxRunner` command policy:
  - blocks path-qualified executables,
  - rejects script arguments that escape the selected repo,
  - scans command text and local Python/JS script contents before execution,
  - blocks destructive patterns such as `shutil.rmtree`, `os.remove`, `.unlink()`, `rm`, `rmdir`, and dangerous git cleanup/reset commands,
  - blocks known network patterns such as `urllib`, `requests`, `httpx`, `socket`, `curl`, `wget`, and install/publish commands when `network_policy` is `deny`.
- Added sandbox environment scrubbing so inherited env vars with `api_key`, `secret`, `token`, or `password` in the name are not exposed to commands.
- Added artifact capture for changed files under `artifacts/` and `reports/`, returned through existing `SandboxRun.artifacts`.
- Added tests for:
  - repo path traversal,
  - script path escape,
  - destructive Python script rejection,
  - network-denied Python script rejection,
  - artifact capture,
  - sensitive environment scrubbing.
- Updated the traceability matrix for PY-012, SBOX-001 through SBOX-006, SEC-009, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 14 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m pytest apps/api/tests`: 22 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: 0 vulnerabilities.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.

Remaining risks:

- Network denial is command/script preflight, not OS-level egress isolation through containers, namespaces, or firewall rules.
- Destructive-operation blocking is pattern-based, not syscall-level.
- Artifact capture returns paths only and watches `artifacts/`/`reports/`; persistent object storage is still pending.
- Explicit secret mounting is not implemented; the current guarantee is environment scrubbing by sensitive key pattern.

## 2026-07-08 - M4 sandbox git diff and AST inspection evidence

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because git diff inspection and AST/static inspection were still called out as pending deterministic evidence for repository claims.

Implemented:

- Added deterministic sandbox inspection report generation at `reports/sandbox-inspection.json`.
- The report includes:
  - `schema_version`.
  - Local git repository status.
  - Staged and unstaged `diff_files`.
  - Combined staged/unstaged diff stat.
  - Python symbols parsed through `ast`, including classes, functions, async functions, methods, qualified names, paths, and line numbers.
  - Parse/inspection errors as report data instead of silent drops.
- Kept the public `SandboxRun` contract unchanged by returning the inspection report through existing `SandboxRun.artifacts`.
- Added tests proving:
  - artifact capture now includes the sandbox inspection report,
  - Python AST inspection reports class/method/async function symbols,
  - local git diff inspection reports a modified tracked file.
- Fixed the endpoint audit contract test so `/repo/checks/run` uses a temporary sandbox workspace instead of writing `reports/` into the repository root.
- Removed the root `reports/sandbox-inspection.json` generated by the pre-fix endpoint test run.
- Updated traceability rows for PY-012, SBOX-005, SBOX-007, SBOX-008, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 16 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 24 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.

Remaining risks:

- The inspection report is deterministic evidence, but `ClaimVerifier` does not yet consume sandbox inspection artifacts to support or reject function/file/diff claims automatically.
- Git inspection is local metadata-based; semantic checks such as “the diff implements Y” still need static analyzers and claim-specific validators.
- Static inspection currently covers Python AST first. TypeScript/JavaScript symbol extraction is still pending.
- Artifact persistence is still local paths only; object storage remains future work.

## 2026-07-08 - M4 deterministic repo claim verifier from sandbox inspection

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because the previous milestone generated sandbox inspection artifacts but `ClaimVerifier` did not yet consume them for repository claims.

Implemented:

- Extended `reports/sandbox-inspection.json` with a bounded `static.files` inventory of inspectable repository files.
- Added deterministic `repo_state` verification in `ClaimVerifier` for:
  - repository file existence claims,
  - Python function/class/method symbol claims from AST inspection,
  - git diff file claims from `git.diff_files`.
- Added sandbox inspection parsing from either `Evidence.structured_content` or JSON `Evidence.content`.
- Changed repo file/function/diff claims so loose textual evidence is not accepted as support when sandbox inspection evidence is missing.
- Made symbol-in-file claims require the requested symbol to appear in the requested file path, not merely somewhere in the repo.
- Added tests proving:
  - a loose text `REPO_FILE` evidence item cannot support `The repo contains service.py`,
  - sandbox file inventory supports a file claim,
  - sandbox AST symbols support `The function fetch exists in service.py`,
  - missing AST symbols are blocked,
  - sandbox git diff evidence supports `The diff modifies service.py`,
  - sandbox static inspection reports `service.py` in `static.files`.
- Updated traceability rows for PY-005, PY-012, SBOX-008, SBOX-009, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 21 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 29 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.

Remaining risks:

- `/repo/checks/run` still returns artifact paths only; callers must currently turn `reports/sandbox-inspection.json` into `Evidence` before `/claims/verify` can consume it.
- Semantic diff claims such as “the diff implements Y” still need deeper static analyzers and claim-specific rules.
- Static symbol verification is Python-first; TypeScript/JavaScript AST extraction remains pending.

## 2026-07-08 - M4 sandbox-run typed evidence bridge

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 bridge slice because `ClaimVerifier` could consume sandbox inspection evidence, but `/repo/checks/run` still exposed only artifact paths.

Implemented:

- Extended public `SandboxRun` in Pydantic, TypeScript, and JSON Schema with typed `evidence`.
- `SandboxRunner` now emits:
  - one `COMMAND_OUTPUT` evidence item per command with command, exit code, stdout, stderr, and network policy,
  - one `REPO_FILE` evidence item for `reports/sandbox-inspection.json` with the full sandbox inspection report in `structured_content`.
- Updated the valid `SandboxRun` JSON example to include command and inspection evidence.
- Added tests proving:
  - sandbox runs return command and inspection evidence,
  - the inspection evidence carries `sandbox_inspection.v1`,
  - `ClaimVerifier` can verify `The function fetch exists in service.py` directly from `SandboxRun.evidence`.
- Updated the MCP live test so `/repo/checks/run` uses a temporary sandbox workspace instead of writing `reports/` into the repository root.
- Cleaned the pre-fix root `reports/sandbox-inspection.json`.
- Updated schema docs and traceability rows for CTR-008, PY-005, PY-012, SBOX-004, SBOX-009, CI-003, and CI-004.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 22 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 42 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming tests did not recreate a repository-root `reports/` artifact.
- `npm --workspace @hallu-defense/sdk run typecheck`: passed.
- `npm --workspace @hallu-defense/mcp-server run typecheck`: passed.
- `npm --workspace @hallu-defense/mcp-server run test`: 6 MCP tests passed and did not recreate root `reports/`.
- `.venv\Scripts\python -m pytest apps/api/tests`: 30 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- `SandboxRun.evidence` is still local/in-memory response data; persistent artifact/evidence storage is pending.
- Semantic diff claims such as “the diff implements Y” still require deeper static analyzers and rule-specific validation.
- Static symbol verification remains Python-first; TypeScript/JavaScript AST extraction remains pending.

## 2026-07-08 - M4 TypeScript and JavaScript static symbol evidence

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because sandbox static inspection and repo claim verification were still Python-first.

Implemented:

- Extended `reports/sandbox-inspection.json` with `static.javascript_symbols`.
- Added conservative static scanning for JavaScript/TypeScript files covering:
  - `class` declarations,
  - top-level `function` declarations,
  - `const`/`let`/`var` arrow functions,
  - function expressions,
  - simple class methods with qualified names like `ApiClient.fetchUser`.
- Added language metadata (`javascript` or `typescript`) to JS/TS symbols.
- Generalized `ClaimVerifier` repo-state symbol lookup to combine `python_symbols` and `javascript_symbols`.
- Updated repo claim verdict text from Python-specific AST wording to generic static inspection wording.
- Added tests proving:
  - sandbox reports TypeScript `ApiClient`, `ApiClient.fetchUser`, `loadUser`, and `parseUser`,
  - `ClaimVerifier` supports TypeScript function and method claims directly from `SandboxRun.evidence`.
- Updated traceability rows for PY-005, PY-012, SBOX-008, SBOX-009, SBOX-010, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 24 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 32 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- The JS/TS scanner is conservative and regex-based. It covers common declarations but is not a full TypeScript AST parser.
- Semantic claims like “the diff implements Y” remain pending and need deeper static analyzers plus rule-specific validators.
- Static extraction still does not cover every language in the inspectable suffix list.

## 2026-07-08 - M4 diff-to-symbol correlation

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because file-level diff evidence was deterministic, but symbol-level diff claims still needed deterministic proof that the named function/class/method was touched.

Implemented:

- Extended sandbox git inspection with:
  - unified hunk parsing from unstaged and staged git diffs,
  - `git.changed_ranges` entries with path, old/new hunk ranges, and source,
  - `git.changed_symbols` entries correlated from changed ranges to nearest Python/TypeScript static symbols.
- Updated `ClaimVerifier` so diff claims that name a code symbol require `git.changed_symbols`, while file-only diff claims continue to use `git.diff_files`.
- Added tests proving:
  - Python body edits correlate to the `fetch` symbol,
  - TypeScript arrow-function edits correlate to the `loadUser` symbol,
  - `The diff updates the function loadUser in service.ts` is supported from `SandboxRun.evidence`,
  - a missing changed symbol in the same file is contradicted and blocked.
- Updated traceability rows for PY-005, PY-012, SBOX-007, SBOX-009, SBOX-011, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 27 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 35 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming tests did not recreate a repository-root `reports/` artifact.

Remaining risks:

- Diff-to-symbol correlation proves a named symbol was touched, not that the change semantically implements the user's intended behavior.
- The TypeScript scanner remains conservative and regex-based; a real TypeScript AST parser can improve recall.
- Git inspection depends on local git metadata and does not yet include container-level isolation or persistent evidence storage.

## 2026-07-08 - M4 implementation claim changed-line evidence

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because `implements/fixes` claims could still be too broad if only file-level diff evidence was considered.

Implemented:

- Extended sandbox git inspection with `git.changed_lines`, capturing added and removed lines from staged and unstaged unified diffs with path, line number, source, kind, and bounded text.
- Hardened repo-state verification for implementation/fix claims:
  - file-only `implements/fixes` claims now need behavior-specific terms in added lines,
  - symbol-specific implementation claims still require `git.changed_symbols`,
  - asserted implementation terms must appear in added lines scoped to the requested file/symbol,
  - vague file-only implementation claims abstain/block instead of being supported by `diff_files` alone.
- Normalized claim file extraction and implementation terms so terminal punctuation such as `service.ts.` does not become a false semantic term.
- Added tests proving:
  - sandbox reports added line evidence,
  - `The diff implements cache in service.ts` is blocked when changed lines do not include `cache`,
  - `The diff implements cache in the function loadUser in service.ts` is supported when `loadUser` is changed and added lines contain `cache`.
- Updated traceability rows for PY-005, PY-012, SBOX-007, SBOX-012, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 29 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 37 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming tests did not recreate a repository-root `reports/` artifact.

Remaining risks:

- Changed-line term matching is deterministic but intentionally conservative; it proves relevant terms appear in changed lines, not arbitrary semantic correctness.
- Claims that need behavioral proof should eventually be tied to focused tests, build commands, or domain-specific analyzers.
- TypeScript static extraction remains regex-based, and sandbox isolation is still process/preflight based rather than container/syscall enforced.

## 2026-07-08 - M4 fix and validation claims require command evidence

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because “fixed”, “validated”, “works”, “tests pass”, and “build passes” claims need command evidence, not only diff/static evidence.

Implemented:

- Added deterministic command-proof classification in `ClaimVerifier` for repo implementation claims that imply validation:
  - test/pass claims require relevant test command evidence,
  - build/compile claims require relevant build/compile command evidence,
  - fixed/validated/works claims require a relevant validation command such as test, build, typecheck, lint, or check.
- Wired implementation verification so:
  - missing relevant command evidence returns `NOT_FOUND` and blocks high-risk claims,
  - failing relevant command evidence returns `CONTRADICTED`,
  - successful relevant command evidence is included in `ClaimVerdict.evidence_ids` and validator trace.
- Kept plain implementation claims like `implements cache` governed by changed-line/symbol evidence from SBOX-012.
- Added token expansion for member expressions such as `cache.get` so changed-line evidence can satisfy the asserted term `cache` without special-casing the word.
- Added tests proving:
  - a cache fix claim is blocked without relevant command evidence,
  - a failing `npm test` command contradicts the fix claim,
  - a passing `npm test` command supports the fix claim together with changed-line/symbol evidence.
- Updated traceability rows for PY-005, SBOX-013, and CI-003.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 32 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 40 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming tests did not recreate a repository-root `reports/` artifact.

Remaining risks:

- Command relevance is keyword-based. A future analyzer should map claims to named test/build targets or changed files more precisely.
- A passing broad command proves only the executed command completed, not complete semantic correctness for every possible behavior.
- Sandbox command execution remains process/preflight based; container/syscall-level isolation is still pending.

## 2026-07-08 - M4 focused command target mapping

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because SBOX-013 still allowed broad successful commands, such as plain `npm test`, to support a specific claim like `fixed cache`.

Implemented:

- Hardened `ClaimVerifier` command evidence matching so fix/validation claims derive target terms from asserted implementation terms, requested files, requested symbols, and changed symbol records.
- Required relevant command evidence to overlap those target terms before it can support or contradict the claim.
- Added a negative verifier test proving a broad successful command is blocked when it does not target the claimed behavior/file/symbol.
- Updated existing failing/successful command tests to use targeted command evidence, such as `npm test -- cache`.
- Added SBOX-014 to the traceability matrix.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 33 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests`: 41 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts/ci/export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios.
- `.venv\Scripts\python scripts/ci/secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests and MCP 6 tests passed.
- `npm run build`: contracts, SDK, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming tests did not recreate a repository-root `reports/` artifact.

Remaining risks:

- Target mapping is lexical and conservative; it proves a command targeted named terms, not full semantic correctness.
- Future work should connect sandbox commands to structured test/build metadata and changed-file based test selection.
- Sandbox command execution remains process/preflight based; container/syscall-level isolation is still pending.

## 2026-07-08 - M4 structured sandbox command metadata

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Selected the next M4 code-agent slice because focused command matching still depended on free-text command/output parsing instead of structured sandbox command metadata.

Implemented:

- Extended sandbox `COMMAND_OUTPUT` evidence with `sandbox_command.v1` metadata:
  - `argv`,
  - `executable`,
  - `command_kind`,
  - `command_target_args`,
  - `command_target_tokens`,
  - `is_targeted`.
- Added deterministic command classification for Python/pytest, npm scripts, and script commands.
- Added deterministic target extraction for focused test/build commands such as `python -m pytest tests/test_cache.py -k cache`.
- Updated `ClaimVerifier` so command class matching prefers structured `command_kind`.
- Updated focused command matching so `command_target_tokens` are authoritative when present; broad commands with empty target metadata no longer pass just because stdout mentions the claimed term.
- Updated the public valid `SandboxRun` example to show the new command metadata.
- Added tests proving sandbox command evidence emits structured targets and verifier logic blocks broad structured commands.
- Added SBOX-015 to the traceability matrix.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 34 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python scripts/ci/check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.

Remaining risks:

- Command metadata is based on deterministic parsing, not full test coverage analysis.
- Future work should connect command targets to changed files/symbols through structured test selection metadata.
- Sandbox command execution remains process/preflight based; container/syscall-level isolation is still pending.

## 2026-07-08 - M5 initial offline eval metrics

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- User approved using multi-agent work with two writing agents; spawned:
  - `Noether` for `packages/agent-adapters/**`.
  - `Kepler` for `apps/console/**`.
- Selected a non-overlapping local slice in `evals` because EVAL-002 still tracked metrics as incomplete.

Implemented:

- Extended `evals/golden_sets/smoke.json` with expected claims and expected unsupported claims.
- Upgraded `evals/runners/smoke.py` to compute and print/write smoke metrics:
  - final decision accuracy,
  - trace coverage,
  - claim ledger coverage,
  - verdict ledger coverage,
  - claim precision,
  - claim recall,
  - unsupported-claim recall,
  - groundedness,
  - faithfulness,
  - false-positive blocking,
  - critical pass-through,
  - p95 latency,
  - cost per run.
- Added threshold checks for critical smoke metrics and p95 latency target.
- Added `evals/reports/smoke-metrics.json` as the generated eval report path.
- Added a unit test for supported/unsupported metric calculation.
- Updated traceability rows for FND-011, PY-015, EVAL-002, and CI-003.

Validation in progress:

- `.venv\Scripts\python evals/runners/smoke.py`: passed for 2 scenarios and wrote `evals/reports/smoke-metrics.json`; metrics included `unsupported_claim_recall=1.0`, `critical_pass_through=0.0`, `false_positive_blocking=0.0`, and p95 latency around 52ms in this run.
- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -q`: 35 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.

Remaining risks:

- The eval set still contains only two smoke scenarios and does not yet cover all required adversarial/security/repo-agent scenarios.
- Metrics are deterministic and useful as gates, but calibration targets need larger golden sets.
- Delegated worker outputs were integrated and validated in the following multi-agent TS entry.

## 2026-07-08 - Multi-agent TS adapters and console panels

Input:

- User explicitly approved using multiple agents and requested two writing agents.
- Spawned two scoped workers:
  - `Noether`: `packages/agent-adapters/**` plus minimal workspace metadata.
  - `Kepler`: `apps/console/**`.
- Main agent kept non-overlapping local work in `evals`, then reviewed and validated worker outputs.

Implemented by worker `Noether`:

- Created `@hallu-defense/agent-adapters`.
- Added provider-agnostic typed helpers:
  - `buildToolCallEnvelope()`,
  - `createAgentToolAdapter()`,
  - pre-tool validation before execution,
  - post-tool validation after execution,
  - sanitized output propagation,
  - typed input/output validation blocked errors.
- Added 4 Vitest tests for envelope construction, execution ordering, input block, and output block.
- Added package workspace metadata and build/typecheck/test scripts.

Implemented by worker `Kepler`:

- Added console policy explanation panel backed by typed SDK `/policy/evaluate`.
- Added console sandbox evidence panel backed by typed SDK `/repo/checks/run`.
- Sandbox panel renders command evidence, exit codes, stdout/stderr snippets, artifacts, `sandbox_command.v1` target tokens, and `sandbox_inspection.v1` diff/static summaries.
- Added console redaction helpers for obvious token/secret patterns in displayed evidence.

Validation after integration:

- `npm run typecheck`: passed across contracts, SDK, agent-adapters, MCP server, and console.
- `npm run test`: SDK 5 tests, agent-adapters 4 tests, MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- Console has build/typecheck/runtime smoke evidence but still lacks browser interaction/e2e tests.
- Agent adapters are generic SDK glue; framework-specific integrations and examples remain future work.
- Policy panel is wired to current Python policy service; formal OPA/Rego policy engine remains pending.

## 2026-07-08 - M5 formal policy and Rego baseline

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Continued the user-approved multi-agent flow:
  - `Banach` updated the `PolicyEvaluationResponse` TypeScript/JSON Schema contract so policy responses require body `trace_id`.
  - `Volta` added scoped Rego policy/test files plus a static Rego CI helper for hosts without `opa`.
- Main agent integrated the runtime API contract, endpoint tests, CI runner, and docs.

Implemented:

- Added required `trace_id` to Python `PolicyEvaluationResponse` and wired `/policy/evaluate` to return the request trace in the response body.
- Replaced the placeholder policy behavior with deterministic enterprise rules for:
  - cross-tenant access denial,
  - secret leakage blocking,
  - PII redaction action,
  - sandbox network review when not denied,
  - repository/test/build claim blocking without deterministic evidence,
  - contradictory tool output repair/block,
  - high-risk and sensitive action human review.
- Added endpoint tests for allow, tenant isolation, high-risk review, secret priority, sandbox network review, and repo-claim deterministic evidence.
- Added `infra/opa/policies/access_risk_approval.rego` and `infra/opa/tests/access_risk_approval_test.rego`.
- Added `scripts/ci/check_rego_policy.py` and `scripts/ci/run_policy_tests.py`.
- Updated `Makefile policy-test` and GitHub Actions backend CI to run the policy test runner.
- Adjusted MCP `explain_policy` output wrapping now that the policy response contract itself includes `trace_id`.

Validation issues found and fixed:

- First `npm run typecheck` failed because MCP specified `trace_id` twice for `explain_policy` structured output.
  - Fix: returned the validated `PolicyEvaluationResponse` directly from MCP for `explain_policy`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -k policy -q`: 7 passed, 34 deselected.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 7 policy tests passed; `opa` not found, static Rego checks passed for 2 files.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 24 source files.
- `.venv\Scripts\python -m pytest apps/api/tests -q`: 49 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and wrote `evals/reports/smoke-metrics.json`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests, agent-adapters 4 tests, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming no repository-root `reports/` artifact was recreated.

Remaining risks:

- `opa` is not installed on this host, so Rego files were statically checked but not executed by the OPA engine.
- The Python policy engine and Rego policy are intentionally aligned at rule intent level, but no runtime OPA adapter calls Rego yet.
- RBAC is still an initial ABAC/policy baseline; OIDC-derived roles and persistent policy bundles remain future work.

## 2026-07-08 - M5 OPA runtime adapter and CI execution

Input:

- User asked to keep working through the existing `/goal` until the full objective is complete.
- Attempted to create a new goal for the full platform, but the goal tool rejected it because the thread already has an unfinished goal.
- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- Spawned two scoped writing agents:
  - `Carson`: CI/OPA runner ownership.
  - `Halley`: Rego parity ownership under `infra/opa/**`.

Implemented:

- Added OPA runtime settings:
  - `HALLU_DEFENSE_OPA_ENABLED`,
  - `HALLU_DEFENSE_OPA_PATH`,
  - `HALLU_DEFENSE_OPA_POLICY_DIR`,
  - `HALLU_DEFENSE_OPA_TIMEOUT_SECONDS`.
- Added `OpaPolicyEvaluator`, which:
  - executes `opa eval` only when enabled and available,
  - builds tenant-aware OPA input,
  - parses strict OPA JSON output,
  - maps decisions into `PolicyEvaluationResponse`,
  - raises explicit policy errors on timeout, invalid output, unsupported action, or nonzero OPA exit.
- Wired `PolicyEngine` to use the optional OPA adapter and fail closed with `opa_policy_evaluation_failed` when enabled OPA evaluation fails.
- Added tests for:
  - OPA disabled fallback,
  - OPA decision mapping from simulated `opa eval`,
  - fail-closed behavior on OPA evaluation error.
- Extended Rego policy and tests for:
  - PII redaction,
  - secret-over-PII precedence,
  - sensitive action review,
  - contradictory tool output repair/block behavior.
- Strengthened `check_rego_policy.py` to require the expanded Rego rule/test identifiers.
- Updated `run_policy_tests.py` to run `opa version` and `opa test infra/opa` when OPA is present.
- Updated GitHub Actions backend CI to install OPA `0.70.0` before policy tests.
- Updated traceability and ADR 0006.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -k "policy or opa" -q`: 10 passed, 34 deselected.
- `.venv\Scripts\python -m pytest apps/api/tests -q`: 52 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 25 source files.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 10 policy tests passed; local `opa` not found on PATH, static Rego checks passed for 2 files.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and wrote `evals/reports/smoke-metrics.json`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed.
- `npm run test`: SDK 5 tests, agent-adapters 4 tests, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `Get-ChildItem reports`: path did not exist, confirming no repository-root `reports/` artifact was recreated.
- Worker `Carson` additionally validated with temporary OPA `0.70.0`: `opa test infra/opa` reported `PASS: 13/13`.

Remaining risks:

- OPA is not installed on this local PATH, so the main local runner used static Rego checks; CI is configured to install OPA.
- The OPA adapter is opt-in and disabled by default until deployment config explicitly enables it.
- Policy bundles are local files; signed bundle distribution and remote policy data are still pending.

## 2026-07-08 - M5 Prometheus API metrics

Input:

- Re-read pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
- User authorized multi-agent usage with at most two writing agents; this slice was implemented by the main agent because it touched API middleware and observability surface.
- Selected OBS-002 because Prometheus metrics were still `not_started`.

Implemented:

- Added a dependency-free Prometheus metrics collector for API build info, HTTP request totals, and HTTP request latency histograms.
- Wired the trace/audit middleware to record every HTTP request using route-template labels, method, status code, and outcome.
- Added `GET /metrics` with Prometheus `text/plain` output while preserving JSON error contracts in OpenAPI.
- Added focused tests for `/metrics` output and OpenAPI text/plain coverage.
- Added Prometheus local scrape config and a `prometheus` service to Docker Compose.
- Updated `docs/PLAN_MASTER.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -k metrics -q`: 2 passed, 43 deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps/api/tests/test_contracts.py -k metrics -q`: 1 passed, 8 deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 26 source files.
- `.venv\Scripts\python -m pytest apps/api/tests -q`: 54 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `docker compose config`: failed because `docker` is not installed or not on PATH on this host.
- `git diff --check`: passed.

Remaining risks:

- Metrics are in-memory and reset on process restart.
- Metrics currently cover HTTP traffic only; domain-specific verification, sandbox, policy, and eval metrics are still pending.
- Docker Compose syntax was not validated locally because Docker is unavailable on this host.

## 2026-07-08 - M5 domain safety metrics

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and the recent `docs/WORKLOG.md` entries.
- Used `senior-programmer` Python guidance for backend instrumentation.
- Selected the next observability slice because OBS-002 still lacked domain-specific verification, policy, approval, and sandbox metrics.

Implemented:

- Extended the Prometheus collector with low-cardinality, non-sensitive domain metrics:
  - `hallu_verification_runs_total`
  - `hallu_verification_run_duration_seconds`
  - `hallu_claim_verdicts_total`
  - `hallu_policy_decisions_total`
  - `hallu_policy_evaluation_duration_seconds`
  - `hallu_approval_requests_total`
  - `hallu_approval_decisions_total`
  - `hallu_sandbox_runs_total`
  - `hallu_sandbox_run_duration_seconds`
- Wired metrics into:
  - verification orchestration after a `VerificationRun` is produced,
  - policy evaluation responses,
  - approval creation and approval decisions,
  - sandbox run success/error paths.
- Added an endpoint-level test that drives `/verification/run`, `/policy/evaluate`, `/tools/validate-input`, `/approvals/decide`, `/repo/checks/run`, and `/metrics`, then checks the emitted Prometheus series.
- Updated `docs/PLAN_MASTER.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- First focused test run failed because `test_core_flow.py` referenced `routes` without importing it.
  - Fix: imported `hallu_defense.api.routes`.
- First mypy run failed because the metrics label callback protocol used an invariant type variable and reused a loop variable across two label types.
  - Fix: split the protocol type variable as contravariant and used distinct loop variable names.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -k "domain_safety_metrics or metrics_endpoint" -q`: 2 passed, 44 deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps/api/src`: passed with no issues in 26 source files.
- `.venv\Scripts\python -m pytest apps/api/tests -q`: 55 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and wrote `evals/reports/smoke-metrics.json`; p95 latency was about 43ms in this run.

Remaining risks:

- Metrics are still in-memory and reset on process restart.
- Prometheus metrics cover core API decisions, but offline eval metrics are still exported as JSON reports rather than scraped series.
- Grafana dashboards and OpenTelemetry tracing remain unimplemented.

## 2026-07-08 - M5 Grafana dashboard provisioning and lint gate

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and recent `docs/WORKLOG.md`.
- Selected OBS-003 because Grafana dashboards were still `not_started`.

Implemented:

- Added Grafana provisioning for:
  - Prometheus datasource at `http://prometheus:9090`.
  - File-based dashboard provider under the `Hallu Defense` folder.
- Added `infra/grafana/dashboards/hallu-defense-overview.json` with 11 panels covering:
  - HTTP request rate and p95 latency,
  - verification run decisions and p95 latency,
  - claim verdicts,
  - policy decisions and p95 latency,
  - approval requests and decisions,
  - sandbox outcomes and p95 latency.
- Added a `grafana` service to `docker-compose.yml` on host port 3001, with sign-up and anonymous auth disabled.
- Added `.env.example` Grafana local admin placeholders.
- Added `scripts/ci/check_grafana_dashboards.py` to validate:
  - dashboard JSON shape,
  - unique panel IDs,
  - required panel titles,
  - required Prometheus metric coverage,
  - Prometheus datasource use,
  - provisioning references,
  - absence of sensitive/free-form query terms.
- Added `dashboard-lint` to `Makefile`.
- Added the dashboard lint script to GitHub Actions backend CI.
- Updated `docs/PLAN_MASTER.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- First dashboard lint run failed because the dashboard did not include `hallu_verification_run_duration_seconds_bucket`.
  - Fix: added a `Verification P95 Latency` panel and made the linter require that panel title.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_grafana_dashboards.py`: validated 1 Grafana dashboard file with 11 panels.
- `.venv\Scripts\python -m ruff check apps/api/src apps/api/tests scripts evals`: passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python -m pytest apps/api/tests/test_core_flow.py -k "domain_safety_metrics or metrics_endpoint" -q`: 2 passed, 44 deselected, 1 FastAPI TestClient deprecation warning.
- `git diff --check`: passed.
- `docker compose config`: failed because `docker` is not installed or not on PATH on this host.

Remaining risks:

- Docker/Grafana runtime rendering is not locally verified because Docker is unavailable on this host.
- Dashboard lint validates structure and query coverage, not visual rendering in a browser.
- OpenTelemetry tracing remains unimplemented.

## 2026-07-08 - M5 OpenTelemetry HTTP request traces

Input:

- Continued the active `/goal`.
- Re-read the pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected OBS-001 because OpenTelemetry tracing was still `not_started`.

Implemented:

- Added OpenTelemetry SDK/exporter dependencies to the API package.
- Added `TelemetryService` with configurable exporters:
  - `memory` for deterministic local tests,
  - `console` for development,
  - `otlp` for collector export.
- Wired FastAPI middleware to create one HTTP span per request with low-cardinality, non-sensitive attributes:
  - `app.trace_id`,
  - `http.request.method`,
  - `url.path`,
  - `http.route`,
  - `http.response.status_code`,
  - `app.outcome`,
  - `app.duration_ms`.
- Added tests proving spans reuse incoming trace IDs, record success/error outcomes, and do not copy tenant IDs, request payloads, tool inputs, or secret-like values into span attributes.
- Added an OpenTelemetry Collector service to Docker Compose and `infra/otel/otel-collector-config.yaml`.
- Added `.env.example` OpenTelemetry settings.
- Updated `docs/PLAN_MASTER.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- First `ruff` run failed because `telemetry.py` imported an unused `Span`.
  - Fix: removed the unused import.
- First `mypy` run failed because the telemetry service annotated the tracer as the SDK tracer type, while `get_tracer()` returns the API tracer type.
  - Fix: imported and used `opentelemetry.trace.Tracer`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_core_flow.py -k opentelemetry -q`: 2 passed, 46 deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 27 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 57 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and wrote `evals/reports/smoke-metrics.json`; p95 latency was 34.622ms in this run.
- `.venv\Scripts\python scripts\ci\check_grafana_dashboards.py`: validated 1 Grafana dashboard file with 11 panels.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python -m pip show opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-http`: all three packages installed at version 1.43.0 in `.venv`.
- `git diff --check`: passed.
- `docker compose config`: failed because `docker` is not installed or not on PATH on this host.

Remaining risks:

- OpenTelemetry collector runtime export was not locally verified because Docker is unavailable.
- The trace exporter is process-local memory by default for tests/local Python execution; Docker Compose switches the API to OTLP.
- Span coverage is currently HTTP request-level; deeper domain spans for retrieval, policy, sandbox commands, and verification stages remain future hardening.

## 2026-07-08 - M5 OpenTelemetry domain-stage traces

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected the next OpenTelemetry hardening slice because the prior OBS-001 entry still listed domain-stage spans as future work.

Implemented:

- Added a generic `TelemetryService.span()` context manager that records exceptions and keeps disabled telemetry as a no-op.
- Instrumented `VerificationOrchestrator.run()` with child spans for:
  - `verification.extract_claims`,
  - `verification.classify_claims`,
  - `verification.retrieve_evidence`,
  - `verification.verify_claims`,
  - `verification.repair_response`.
- Instrumented `/policy/evaluate` with a `policy.evaluate` span containing only risk level, decision action, allowed flag, rule count, outcome, and trace ID.
- Instrumented `/repo/checks/run` with a `sandbox.run` span containing only command count, network policy, verdict/outcome, and trace ID.
- Added tests proving domain spans are parented under the request span and do not include tenant IDs, payload text, document source refs, repo refs, command strings, or secret-like values.

Validation issues found and fixed:

- First focused test run expected `require_human_review` for a policy request whose test attributes included `tenant_id`, which correctly triggered the cross-tenant block rule first.
  - Fix: kept the sensitive marker inside an inert note attribute so the test still verifies non-leakage without changing policy behavior.
- First `mypy` run inferred mixed span attributes as `object`.
  - Fix: typed the base verification span attribute map as `dict[str, AttributeValue]`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_core_flow.py -k opentelemetry -q`: 5 passed, 46 deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 27 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 60 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote `docs/api/openapi.yaml`.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and wrote `evals/reports/smoke-metrics.json`; p95 latency was 31.376ms in this run.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- OpenTelemetry collector runtime export remains unverified on this host because Docker is unavailable.
- Domain spans now cover current in-process verification/policy/sandbox flows; future OpenSearch/pgvector and persistent audit/storage adapters should add their own spans when implemented.

## 2026-07-08 - M5 encryption configuration baseline

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected SEC-008 because encryption configuration was still `not_started`.

Implemented:

- Added `infra/security/encryption-policy.json` as the versioned encryption baseline for:
  - API,
  - console,
  - PostgreSQL/pgvector,
  - Redis,
  - MinIO,
  - Prometheus,
  - Grafana,
  - OpenTelemetry collector,
  - future OpenSearch.
- Added `scripts/ci/check_encryption_config.py`, which validates:
  - schema version,
  - TLS 1.3 minimum,
  - no plaintext external interfaces,
  - AES-256-class at-rest encryption,
  - non-plaintext key management,
  - non-empty data classes,
  - explicit local-development exemptions.
- Added `apps/api/tests/test_security_config.py` with positive and negative tests for:
  - valid enterprise defaults,
  - plaintext external interface rejection,
  - weak TLS rejection,
  - plaintext/local key-management rejection.
- Added `docs/security/encryption.md` and updated `SECURITY.md`.
- Wired the encryption config check into:
  - `Makefile` target `encryption-config`,
  - `Makefile security-check`,
  - `.github/workflows/ci.yml`,
  - `.github/workflows/security.yml`.
- Hardened `scripts/ci/secret_scan.py` so unreadable files produce a clear failing report instead of a traceback.
- Updated `docs/PLAN_MASTER.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation notes:

- An initial concurrent `secret_scan.py` run hit a transient `PermissionError`. A direct filesystem probe did not find a persistently unreadable file, and a re-run passed. The scanner was then hardened to report unreadable files explicitly.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy with 9 components.
- `.venv\Scripts\python -m pytest apps\api\tests\test_security_config.py -q`: 4 passed.
- `.venv\Scripts\python -m ruff check scripts\ci\check_encryption_config.py apps\api\tests\test_security_config.py`: passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 27 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 64 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- The new policy and validator prove configuration intent and CI enforcement only.
- Runtime proof that Docker/Kubernetes services use TLS and encrypted volumes remains future deploy-hardening work.
- Container image scanning is still pending under CI/security risks.

## 2026-07-08 - M5 Python dependency audit gate

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected SEC-007 because dependency audit still had Python audit pending.

Implemented:

- Added `pip-audit>=2.7.0,<3.0.0` to the API dev dependencies.
- Added `scripts/ci/python_dependency_audit.py`, a wrapper that:
  - verifies `pip-audit` is installed,
  - runs `python -m pip_audit --progress-spinner off`,
  - returns the real audit exit code for CI.
- Added `apps/api/tests/test_python_dependency_audit.py` for:
  - command construction,
  - missing-tool reporting,
  - propagation of pip-audit failure exit codes.
- Wired the Python audit into:
  - `Makefile` target `python-audit`,
  - `Makefile security-check`,
  - `.github/workflows/ci.yml`,
  - `.github/workflows/security.yml`.
- Updated `pytest` dev dependency from `>=8.3.0,<9.0.0` to `>=9.0.3,<10.0.0` after the audit found a vulnerability.
- Updated `SECURITY.md`, `docs/PLAN_MASTER.md`, and `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- First real audit failed:
  - `pytest 8.4.2`
  - vulnerability `PYSEC-2026-1845`
  - fixed versions: `9.0.3`
- Fix:
  - updated API dev dependency to `pytest>=9.0.3,<10.0.0`,
  - reinstalled `apps/api[dev]`,
  - environment now has `pytest 9.1.1`.

Validation after fixes:

- `.venv\Scripts\python -m pip install -e "apps/api[dev]"`: installed `pip-audit 2.10.1` and upgraded `pytest` to 9.1.1.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `.venv\Scripts\python -m pytest apps\api\tests\test_python_dependency_audit.py -q`: 3 passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 27 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 67 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `.venv\Scripts\python -m pip show pytest pip-audit`: `pytest 9.1.1`, `pip_audit 2.10.1`.
- `git diff --check`: passed.

Remaining risks:

- `pip-audit` checks published Python packages; it cannot audit the local editable `hallu-defense-api` package as if it were a PyPI artifact.
- Container image scanning remains pending as a separate CI/security requirement.

## 2026-07-08 - M5 container image scanning gate

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected the container scanning risk because CI/security still listed it as pending.

Implemented:

- Hardened Dockerfiles:
  - API image now creates and runs as non-root `appuser`.
  - Console image now uses `npm ci` instead of `npm install` and runs as non-root `node`.
- Extended `.github/workflows/security.yml` to:
  - validate container scan config locally before scan steps,
  - build `hallu-defense-api:ci` from `infra/docker/api.Dockerfile`,
  - scan the API image with `aquasecurity/trivy-action@0.28.0`,
  - build `hallu-defense-console:ci` from `infra/docker/console.Dockerfile`,
  - scan the console image with `aquasecurity/trivy-action@0.28.0`,
  - fail on HIGH or CRITICAL OS/library vulnerabilities with `exit-code: "1"`,
  - avoid `continue-on-error`.
- Added `scripts/ci/check_container_scan_config.py`, which validates:
  - both required images are built and scanned,
  - Trivy action refs are pinned to a released version rather than a branch,
  - scans fail on findings,
  - HIGH/CRITICAL severity and OS/library vulnerability types are configured,
  - Dockerfiles set non-root users,
  - Dockerfiles do not use `latest` base images or remote `ADD`,
  - Python image installs without pip cache,
  - console image uses `npm ci`.
- Added `apps/api/tests/test_container_scan_config.py` with positive and negative tests.
- Added `docs/security/container-scanning.md`.
- Added `container-scan-config` to `Makefile` and included it in `security-check`.
- Updated `SECURITY.md`, `docs/PLAN_MASTER.md`, and `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated container scan config for 2 images.
- `.venv\Scripts\python -m pytest apps\api\tests\test_container_scan_config.py -q`: 4 passed.
- `.venv\Scripts\python -m ruff check scripts\ci\check_container_scan_config.py apps\api\tests\test_container_scan_config.py`: passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 27 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 71 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas, 33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.
- `docker build -f infra\docker\api.Dockerfile -t hallu-defense-api:ci .`: failed because `docker` is not installed or not on PATH on this host.
- `docker build -f infra\docker\console.Dockerfile -t hallu-defense-console:ci .`: failed because `docker` is not installed or not on PATH on this host.

Remaining risks:

- Local Docker image build and Trivy runtime scan could not be executed on this host because Docker is unavailable.
- Runtime container scan evidence must come from GitHub Actions.

## 2026-07-08 - M5 Vault-compatible secret manager integration

Input:

- Continued the active `/goal`.
- Re-read the original pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected SEC-010 because the traceability matrix still listed Vault-compatible secrets as documented only with implementation pending.

Implemented:

- Added API secret manager configuration for:
  - `HALLU_DEFENSE_SECRETS_BACKEND`,
  - `HALLU_DEFENSE_ENV_SECRET_PREFIX`,
  - `HALLU_DEFENSE_VAULT_ADDR`,
  - `HALLU_DEFENSE_VAULT_MOUNT`,
  - `HALLU_DEFENSE_VAULT_NAMESPACE`,
  - `HALLU_DEFENSE_VAULT_TOKEN_ENV`,
  - `HALLU_DEFENSE_VAULT_TIMEOUT_SECONDS`.
- Added `SecretManager` with:
  - local `EnvSecretManager` restricted to local/test/dev/CI,
  - Vault KV v2-compatible `VaultSecretManager`,
  - `SecretValue` redaction for string and repr output,
  - relative secret-name validation and traversal rejection,
  - production/staging startup failure if the env backend is selected,
  - production/staging startup failure if Vault is selected without a token env value.
- Wired the secret manager into API dependencies as an application-level service.
- Added `infra/security/secrets-policy.json`.
- Added `scripts/ci/check_secrets_config.py` and wired it into Makefile, backend CI, and security CI.
- Added `docs/security/secrets.md` and updated `.env.example` and `SECURITY.md`.
- Added focused tests for manager behavior and secrets-policy validation.

Validation issues found and fixed:

- Initial `secret_scan.py` reported a potential secret in `apps/api/tests/test_secret_manager.py` because local variables named `secret` looked like assignments to credentials.
  - Fix: renamed the local variables to avoid secret-like assignment patterns while keeping the redaction assertions.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated Vault-compatible secrets configuration.
- `.venv\Scripts\python -m pytest apps\api\tests\test_secret_manager.py apps\api\tests\test_secrets_config.py -q`: 10 passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 28 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 81 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- Runtime connectivity to a deployed Vault-compatible service is not exercised locally.
- The secret manager is now wired as a service, but provider adapters do not yet consume managed credentials.

## 2026-07-08 - M5 provider adapter abstraction

Input:

- Continued the active `/goal`.
- Re-read the original pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected provider abstraction because the product requires OpenAI-compatible, Ollama/local, and mock providers, and the prior SEC-010 risk noted that no adapter consumed managed secrets.

Implemented:

- Added `hallu_defense.services.providers` with:
  - `ModelProvider` protocol,
  - `ProviderMessage`, `ProviderRequest`, and `ProviderResponse`,
  - deterministic `MockModelProvider`,
  - OpenAI-compatible `/chat/completions` adapter,
  - Ollama `/api/chat` adapter,
  - injectable JSON transport for deterministic tests,
  - factory selection from settings.
- Added provider configuration:
  - `HALLU_DEFENSE_PROVIDER_BACKEND`,
  - `HALLU_DEFENSE_PROVIDER_MODEL`,
  - `HALLU_DEFENSE_PROVIDER_TIMEOUT_SECONDS`,
  - `HALLU_DEFENSE_OPENAI_COMPATIBLE_BASE_URL`,
  - `HALLU_DEFENSE_OPENAI_COMPATIBLE_API_KEY_SECRET_NAME`,
  - `HALLU_DEFENSE_OLLAMA_BASE_URL`,
  - `HALLU_DEFENSE_MOCK_PROVIDER_RESPONSE`.
- Wired the selected provider into API dependencies.
- Updated `.env.example`, `SECURITY.md`, `docs/security/providers.md`, `docs/PLAN_MASTER.md`, and `docs/TRACEABILITY_MATRIX.md`.
- Added focused provider adapter tests proving:
  - mock provider is deterministic and network-free,
  - OpenAI-compatible adapter reads credentials via `SecretManager`,
  - OpenAI-compatible payload/header/timeout shape is deterministic,
  - missing credentials fail closed,
  - Ollama adapter uses the local chat endpoint without an authorization header,
  - mock backend is rejected in production-like environments,
  - malformed provider requests are rejected.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_provider_adapters.py -q`: 6 passed.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\providers.py apps\api\tests\test_provider_adapters.py`: passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 29 source files.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 87 passed, 1 FastAPI TestClient deprecation warning.

Remaining risks:

- Runtime provider connectivity is not verified locally; tests use injected transports and no network.
- The claim verifier still uses deterministic lexical/numeric checks; NLI/provider-backed scoring remains a future slice.

## 2026-07-08 - M5 provider-backed NLI adjudication fallback

Input:

- Continued the active `/goal`.
- Re-read the original pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected PY-017 because PY-005 still listed provider/NLI scoring as not wired into claim verification.

Implemented:

- Added `hallu_defense.services.nli` with:
  - `NliAdjudicator` protocol,
  - `ProviderNliAdjudicator`,
  - strict JSON output parsing,
  - allowed statuses: `supported`, `contradicted`, `insufficient_evidence`,
  - evidence-ID validation,
  - secret-like text redaction before provider prompting,
  - document/web-only scope.
- Added `HALLU_DEFENSE_PROVIDER_NLI_ENABLED`, disabled by default.
- Wired the optional adjudicator into API dependencies and `ClaimVerifier`.
- Integrated NLI only as a fallback after deterministic textual checks do not support the claim.
- Kept deterministic branches separate:
  - repo claims still require sandbox/static/git evidence,
  - test/build claims still require command evidence,
  - tool claims still use tool evidence.
- Added provider NLI docs under `docs/security/providers.md`.
- Hardened `secret_scan.py` to skip `.mypy_cache` and `.ruff_cache`; the first security scan after mypy failed on `.mypy_cache\3.12\cache.db-shm`, which is a transient tool cache file.

Validation issues found and fixed:

- Initial NLI tests used evidence with strong lexical overlap, so the verifier correctly resolved deterministically before invoking NLI.
  - Fix: changed the fixture to use low-overlap evidence so the NLI fallback path is actually exercised.
- `ruff` found two unused imports in the first implementation.
  - Fix: removed the unused imports.
- `secret_scan.py` initially failed after mypy because it attempted to read `.mypy_cache\3.12\cache.db-shm`.
  - Fix: added `.mypy_cache` and `.ruff_cache` to skipped directories.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_nli_adjudicator.py -q`: 7 passed.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\nli.py apps\api\src\hallu_defense\services\verifier.py apps\api\tests\test_nli_adjudicator.py`: passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 30 source files.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`: passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 94 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- Provider NLI is disabled by default and not calibrated against a real model.
- Runtime provider connectivity is not verified locally; tests use deterministic injected providers/transports.

## 2026-07-08 - M5 backup/restore and retention policy baseline

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`,
  `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected SEC-012 because M5 still required backup/restore and retention policy docs.

Implemented:

- Added `infra/security/backup-retention-policy.json` with:
  - retention classes for audit ledger, verification runs, approvals, evidence indexes,
    artifacts, eval reports, observability, and short-lived cache data,
  - encrypted backup requirements for persistent components,
  - explicit RPO/RTO/frequency/target fields,
  - restore drill intervals capped at 90 days,
  - tenant-scoped deletion and audit-event requirements.
- Added `scripts/ci/check_backup_retention_config.py`, which validates:
  - required components,
  - backup encryption,
  - persistent backup enablement,
  - restore drill cadence,
  - retention minimums,
  - tenant-scoped deletion,
  - Makefile, CI workflow, security workflow, `SECURITY.md`, and docs wiring.
- Added `apps/api/tests/test_backup_retention_config.py` with positive and negative tests.
- Added `docs/security/backup-restore-retention.md`.
- Wired the gate into `Makefile`, `.github/workflows/ci.yml`, and
  `.github/workflows/security.yml`.
- Updated `SECURITY.md`, `docs/PLAN_MASTER.md`, and `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- Initial `check_backup_retention_config.py` failed because the support-file validator
  compared the `SECURITY.md` phrase case-sensitively.
  - Fix: normalized the security document text to lowercase before checking for the policy phrase.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python -m pytest apps\api\tests\test_backup_retention_config.py -q`:
  6 passed.
- `.venv\Scripts\python -m ruff check scripts\ci\check_backup_retention_config.py apps\api\tests\test_backup_retention_config.py`:
  passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 30 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 100 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy
  with 9 components.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated Vault-compatible
  secrets configuration.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated container
  scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities
  found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- This is policy and CI evidence only; it does not execute database dumps, object snapshots,
  OpenSearch snapshots, or restore jobs on this host.
- Runtime backup schedules, restore drill artifacts, and Kubernetes storage integration remain
  future deployment hardening work.

## 2026-07-08 - M2 persistent RAG index adapter boundary

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`,
  recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected RAG-003/RAG-004 because the matrix still listed OpenSearch and pgvector adapter
  work as pending.

Implemented:

- Added `hallu_defense.services.rag_index` with:
  - `RagIndexBackend` protocol,
  - tenant-scoped `RagChunk` and `RagSearchRequest`,
  - `OpenSearchRagIndexBackend`,
  - `PgVectorRagIndexBackend`,
  - deterministic hash embedder for offline tests,
  - safe identifier validation,
  - transport/connection protocols for deterministic tests without network or database runtime.
- Integrated `HybridRetriever` with an optional persistent backend:
  - inline document ranking remains the default local path,
  - `index_documents()` converts inline documents into tenant-scoped persistent chunks,
  - `/evidence/retrieve` now passes request tenant, `context_refs`, and `metadata_filter`
    to persistent search when a backend is configured.
- Added RAG index configuration:
  - `HALLU_DEFENSE_RAG_INDEX_BACKEND`,
  - `HALLU_DEFENSE_RAG_INDEX_TIMEOUT_SECONDS`,
  - `HALLU_DEFENSE_OPENSEARCH_ENDPOINT`,
  - `HALLU_DEFENSE_OPENSEARCH_INDEX_NAME`,
  - `HALLU_DEFENSE_PGVECTOR_TABLE_NAME`,
  - `HALLU_DEFENSE_RAG_EMBEDDING_DIMENSION`.
- Added `docs/rag/persistent-indexes.md`.
- Updated `docs/PLAN_MASTER.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- First broad `ruff` run failed because `DeterministicHashEmbedder` was imported in
  `services/__init__.py` but missing from `__all__`.
  - Fix: added `DeterministicHashEmbedder` to `__all__`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py -q`:
  9 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\rag_index.py apps\api\src\hallu_defense\services\retrieval.py apps\api\tests\test_rag_index_adapters.py`:
  passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 31 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 109 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 33 schemas,
  33 valid examples, 33 invalid examples, and 33 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy
  with 9 components.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated Vault-compatible
  secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated backup/restore
  and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated container
  scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities
  found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- OpenSearch and pgvector are adapter boundaries, not live runtime integrations.
- Runtime OpenSearch service wiring, index templates, pgvector migrations, database connection
  pools, durable ingestion workers, and live integration tests remain pending.

## 2026-07-08 - M2 document ingestion API and public contracts

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`,
  recent `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected document ingestion because the previous RAG slice added persistent index adapters
  but no public tenant-scoped ingestion surface.

Implemented:

- Added Pydantic contracts:
  - `DocumentIngestionRequest`,
  - `DocumentIngestionResponse`.
- Added `DocumentIngestionService`, which:
  - applies `corpus_id` metadata before indexing,
  - uses request tenant context for index writes,
  - returns trace ID, tenant ID, corpus ID, backend, document count, indexed count,
    evidence IDs, and warnings,
  - explicitly warns when the default `local` backend validates but does not persist documents.
- Added `POST /documents/ingest`.
- Added TypeScript contracts and SDK method `ingestDocuments()`.
- Added MCP tool `ingest_documents` with shared JSON Schema input/output validation.
- Added JSON Schemas and valid/invalid examples for document ingestion request/response.
- Updated OpenAPI output in `docs/api/openapi.yaml`.
- Updated `docs/rag/persistent-indexes.md`, `docs/schemas/README.md`,
  `docs/PLAN_MASTER.md`, and `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 35 schemas,
  35 valid examples, 35 invalid examples, and 35 TypeScript interfaces.
- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py apps\api\tests\test_contracts.py -q`:
  21 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\ingestion.py apps\api\src\hallu_defense\domain apps\api\src\hallu_defense\api apps\api\tests\test_rag_index_adapters.py apps\api\tests\test_contracts.py`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 32 source files.
- `npm --workspace @hallu-defense/sdk run test`: 6 passed.
- `npm --workspace @hallu-defense/mcp-server run typecheck`: passed.
- `npm --workspace @hallu-defense/mcp-server run test`: 6 passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated `docs/api/openapi.yaml`.
- `rg -n "documents/ingest|DocumentIngestion" docs\api\openapi.yaml`: confirmed the
  path and schemas are present.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 112 passed, 1 FastAPI
  TestClient deprecation warning.
- `npm run typecheck`: passed for all workspaces.
- `npm run test`: SDK 6, agent-adapters 4, MCP 6 passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption policy
  with 9 components.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated Vault-compatible
  secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated backup/restore
  and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated container
  scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known vulnerabilities
  found; local editable `hallu-defense-api` was skipped because it is not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `npm run build`: passed for contracts, SDK, agent-adapters, MCP server, and Next console.
- `git diff --check`: passed.

Remaining risks:

- The ingestion endpoint is live and contract-covered, but default local mode does not persist.
- Runtime OpenSearch service wiring, pgvector migrations/connection pools, durable ingestion
  workers, and live integration tests remain pending.

## 2026-07-08 - M2 RAG persistence runtime artifacts and CI gate

Input:

- Continued the active `/goal`.
- Re-read the pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`,
  `docs/TRACEABILITY_MATRIX.md`, `docs/WORKLOG.md`, and the Python senior-programmer
  reference.
- Selected RAG persistence runtime artifacts because ingestion and adapter boundaries
  existed, but pgvector/OpenSearch deployment artifacts and a static CI gate were still
  missing.

Implemented:

- Added `infra/rag/pgvector/001_rag_evidence_chunks.sql` with the `vector`
  extension, tenant-scoped `rag_evidence_chunks` table, `(tenant_id, evidence_id)`
  primary key, metadata GIN index, tenant/source index, and vector cosine index.
- Added `infra/rag/opensearch/evidence-index-template.json` with `dynamic: false`,
  tenant/source keyword fields, analyzed content, metadata object support, and
  `_meta.required_query_filter=tenant_id`.
- Updated `docker-compose.yml` to add a pinned local OpenSearch service, configure
  the API with `HALLU_DEFENSE_RAG_INDEX_BACKEND=opensearch`, wire the OpenSearch
  endpoint/index name, depend on OpenSearch, and mount pgvector migrations into
  Postgres initialization.
- Marked OpenSearch as an active component in encryption and backup/retention policy
  baselines.
- Added `scripts/ci/check_rag_persistence_config.py` and
  `apps/api/tests/test_rag_persistence_config.py` to validate the pgvector migration,
  OpenSearch template, Compose backend wiring, Makefile target, CI workflow, and
  security workflow, including negative cases for tenant isolation, pinned images,
  Compose backend wiring, Makefile wiring, and CI wiring.
- Wired the new gate into `Makefile`, `.github/workflows/ci.yml`, and
  `.github/workflows/security.yml`.
- Updated RAG and backup/retention docs plus `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_persistence_config.py -q`:
  7 passed.
- `.venv\Scripts\python -m ruff check scripts\ci\check_rag_persistence_config.py apps\api\tests\test_rag_persistence_config.py`:
  passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 32 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 119 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.
- `docker compose config`: failed because `docker` is not installed or not on PATH on
  this host.

Remaining risks:

- Static validators prove artifact shape and CI wiring, not a running OpenSearch
  cluster or pgvector database.
- OpenSearch template installation, pgvector connection pools, live migration execution
  evidence, health checks, and live integration tests remain pending.
- Docker Compose runtime could not be validated locally because Docker is unavailable.

## 2026-07-08 - M2 OpenSearch template bootstrap command

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`,
  `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected the OpenSearch template bootstrap slice because runtime artifacts existed,
  but there was no executable path to install the template or dry-run it in CI.

Implemented:

- Added `OpenSearchRagIndexBackend.install_index_template()`, which validates template
  names and template payload shape, then builds `PUT /_index_template/{template_name}`
  through the existing injectable OpenSearch transport.
- Added `OpenSearchTemplateInstallResult` and exported it from `hallu_defense.services`.
- Added `scripts/dev/bootstrap_opensearch_template.py` with:
  - defaults from API settings,
  - `--dry-run` validation without contacting OpenSearch,
  - normal mode that fails closed unless OpenSearch returns `acknowledged: true`,
  - JSON output for runbook/CI evidence.
- Wired `bootstrap_opensearch_template.py --dry-run` into `Makefile`,
  `.github/workflows/ci.yml`, and `.github/workflows/security.yml`.
- Extended `scripts/ci/check_rag_persistence_config.py` so the RAG persistence gate
  also requires bootstrap dry-run wiring.
- Added focused tests for backend template installation, unsafe template names, invalid
  template payloads, CLI dry-run, acknowledged install, and unacknowledged install
  failure.
- Updated `docs/rag/persistent-indexes.md` and `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py apps\api\tests\test_opensearch_bootstrap.py apps\api\tests\test_rag_persistence_config.py -q`:
  27 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\rag_index.py apps\api\src\hallu_defense\services\__init__.py scripts\dev\bootstrap_opensearch_template.py apps\api\tests\test_rag_index_adapters.py apps\api\tests\test_opensearch_bootstrap.py apps\api\tests\test_rag_persistence_config.py scripts\ci\check_rag_persistence_config.py`:
  passed.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned JSON with `dry_run: true`, `installed: false`, and the local template path.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 32 source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 127 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.
- `docker compose config`: failed because `docker` is not installed or not on PATH on
  this host.

Remaining risks:

- The bootstrap command is covered by dry-run and fake-transport tests, but has not
  been executed against a live OpenSearch cluster on this host.
- OpenSearch health checks, a live ingest/retrieve integration test, pgvector connection
  pools, runtime migration execution evidence, and backfill workers remain pending.
- Docker Compose runtime remains unverified locally because Docker is unavailable.

## 2026-07-08 - M5 persistent audit ledger baseline

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`,
  `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected audit persistence because the matrix still listed append-only audit storage
  as pending and the product requires an active audit ledger.

Implemented:

- Added optional JSONL append-only persistence to `AuditLedger`.
- Added audit ledger configuration:
  - `HALLU_DEFENSE_AUDIT_LEDGER_BACKEND`,
  - `HALLU_DEFENSE_AUDIT_LEDGER_PATH`.
- Added `create_audit_ledger(settings)`, which rejects the `memory` backend in
  production/staging and creates the JSONL-backed ledger when configured.
- Wired the API dependency container through the audit ledger factory.
- Added redaction/minimization before storing verification runs and audit event
  metadata; sensitive-looking keys/text are stored as `[REDACTED]`.
- Added fail-closed handling for corrupt or unsupported JSONL records.
- Added `docs/security/audit-ledger.md` and updated `SECURITY.md`.
- Added `scripts/ci/check_audit_ledger_config.py`, Makefile target, CI workflow step,
  and security workflow step.
- Added focused tests for JSONL persistence/reload, tenant/trace filtering, redaction,
  production memory-backend rejection, JSONL production acceptance, corrupt-record
  failure, and config-gate negative cases.
- Updated `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_audit_ledger.py apps\api\tests\test_audit_ledger_config.py -q`:
  10 passed.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\audit.py apps\api\src\hallu_defense\config.py apps\api\src\hallu_defense\api\dependencies.py apps\api\src\hallu_defense\services\__init__.py apps\api\tests\test_audit_ledger.py apps\api\tests\test_audit_ledger_config.py scripts\ci\check_audit_ledger_config.py`:
  passed after removing an unused import.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 32 source files.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 137 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- JSONL provides local append-only durability, not a distributed database/object-store
  audit ledger.
- Runtime retention jobs, object replication, restore drills, and production storage
  integrations remain deployment work.

## 2026-07-08 - M3 persistent approval queue baseline

Input:

- Continued the active `/goal`.
- Re-read the pasted objective, `AGENTS.md`, `docs/PLAN_MASTER.md`,
  `docs/TRACEABILITY_MATRIX.md`, `docs/WORKLOG.md`, and the Python senior-programmer
  reference.
- Selected approval persistence because `PY-011`, `CTR-023`, `API-014`, and
  `API-015` still listed in-memory approval state or persistent queue risk.

Implemented:

- Added optional JSONL append-only persistence to `ApprovalQueue`.
- Added approval queue configuration:
  - `HALLU_DEFENSE_APPROVAL_QUEUE_BACKEND`,
  - `HALLU_DEFENSE_APPROVAL_QUEUE_PATH`.
- Added `create_approval_queue(settings)`, which rejects the `memory` backend in
  production/staging and creates the JSONL-backed queue when configured.
- Wired the API dependency container through the approval queue factory.
- Persisted approval request and decision snapshots with replay of the latest state
  per `approval_id`.
- Kept tenant isolation and repeated-decision checks after reload.
- Redacted sensitive-looking tool input, tool schema, and caller context values before
  storage.
- Added fail-closed handling for corrupt or unsupported JSONL records.
- Added `docs/security/approvals.md` and updated `SECURITY.md`.
- Added `scripts/ci/check_approval_queue_config.py`, Makefile target, CI workflow
  step, and security workflow step.
- Added focused tests for JSONL persistence/reload, decision replay, tenant isolation,
  repeated-decision blocking, redaction, production memory-backend rejection, JSONL
  production acceptance, corrupt-record failure, and config-gate negative cases.
- Updated `docs/TRACEABILITY_MATRIX.md`.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_approval_queue.py apps\api\tests\test_approval_queue_config.py -q`:
  14 passed.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\approvals.py apps\api\src\hallu_defense\config.py apps\api\src\hallu_defense\api\dependencies.py apps\api\src\hallu_defense\services\__init__.py apps\api\tests\test_approval_queue.py apps\api\tests\test_approval_queue_config.py scripts\ci\check_approval_queue_config.py`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 32 source
  files.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 151 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template` without contacting OpenSearch.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- JSONL provides local append-only durability, not a distributed database/object-store
  approval queue.
- Reviewer identity is still caller-supplied until OIDC/RBAC integration lands.
- Execution-token enforcement after approval is still pending.

## 2026-07-08 - M3 approval execution grant enforcement

Input:

- Continued the active `/goal`.
- Re-read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`,
  `docs/WORKLOG.md`, and the Python senior-programmer reference.
- Selected approval execution-token enforcement because the previous approval slice left
  the post-approval handoff as an explicit risk.

Implemented:

- Added `ApprovalExecutionGrant` to Pydantic, TypeScript, JSON Schema, examples, and
  OpenAPI.
- Extended `ToolCallEnvelope` with optional `approval_id` and
  `approval_execution_token`.
- Changed `/approvals/decide` so approved decisions return a bounded execution grant.
  Rejected decisions return `execution_grant: null`.
- Added one-time grant enforcement to `/tools/validate-input`:
  - grants are tenant scoped,
  - bound to approval ID and sanitized tool-call fingerprint,
  - time bounded by `HALLU_DEFENSE_APPROVAL_EXECUTION_GRANT_TTL_SECONDS`,
  - stored as a hash in JSONL,
  - consumed on first successful validation,
  - rejected with 403 on reuse, expiry, invalid token, or mismatched tool call.
- Added approval grant state replay and consumption persistence to `ApprovalQueue`.
- Added typed agent-adapter support for attaching approval grants to tool envelopes.
- Updated approval security docs, schema inventory, approval queue config gate, and
  traceability matrix.

Validation issues found and fixed:

- The approval config gate initially failed because it searched for the old
  single-line `ApprovalQueue(storage_path` constructor snippet. Updated the gate to
  validate stable factory wiring instead.
- `@hallu-defense/agent-adapters` typecheck failed under `exactOptionalPropertyTypes`
  because `approvalGrant: undefined` was passed explicitly. Fixed by conditionally
  including the optional property.
- `secret_scan.py` flagged a local variable named `token` assigned from
  `secrets.token_urlsafe(...)`. Renamed it to avoid weakening the scanner or adding
  allowlists.

Validation after fixes:

- `.venv\Scripts\python -m pytest apps\api\tests\test_approval_queue.py apps\api\tests\test_approval_queue_config.py apps\api\tests\test_core_flow.py -q`:
  70 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python -m pytest apps\api\tests\test_contracts.py -q`: 9 passed,
  1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 32 source
  files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 156 passed, 1 FastAPI
  TestClient deprecation warning.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build
  passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template` without contacting OpenSearch.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- Reviewer identity is still caller-supplied until OIDC/RBAC integration lands.
- JSONL stores hashed grant state locally; distributed queue storage remains deployment
  work.
- There is still no real tool execution endpoint; enforcement currently happens at the
  pre-tool validation boundary and through typed adapters.

## 2026-07-08 - M3 approval reviewer RBAC boundary

Slice selected:

- Selected the smallest security slice left by the approval grant work: remove
  caller-controlled reviewer identity from `/approvals/decide` and require a reviewer
  role before issuing an approval decision.
- Implemented by the main agent because the changes touch auth context, API routing,
  public contracts, and approval persistence behavior.

Implementation:

- Added `services/auth.py` with an OIDC-ready `Principal`, `AuthenticationError`,
  `AuthorizationError`, role parsing, and `approval_reviewer` role constant.
- Extended `RequestContext` to carry `principal` from `Authorization`,
  `x-subject-id`, and `x-roles` headers. When `HALLU_DEFENSE_AUTH_REQUIRED=true`,
  missing authorization or subject now returns 401.
- Changed `POST /approvals/decide` to require `approval_reviewer`, return 403 without
  the role, and overwrite `ApprovalDecisionRequest.decided_by` from the request
  principal instead of trusting the body.
- Kept `ApprovalDecisionRequest.decided_by` optional/deprecated for compatibility and
  made the approval queue reject direct decision calls without reviewer identity.
- Updated TypeScript contracts, JSON Schema, schema examples, SDK options, SDK tests,
  and console approval calls for `subjectId`/`roles`.
- Added `docs/security/auth-rbac.md`, updated approval/security/schema docs, and
  refreshed `docs/api/openapi.yaml`.
- Updated `docs/TRACEABILITY_MATRIX.md` for `CTR-023`, `API-015`, `PY-011`,
  `SEC-001`, `SEC-002`, `SEC-003`, and `CI-003`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_auth.py apps\api\tests\test_approval_queue.py apps\api\tests\test_core_flow.py -q`:
  69 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\auth.py apps\api\src\hallu_defense\api\dependencies.py apps\api\src\hallu_defense\api\routes.py apps\api\src\hallu_defense\domain\models.py apps\api\src\hallu_defense\services\approvals.py apps\api\tests\test_auth.py apps\api\tests\test_approval_queue.py apps\api\tests\test_core_flow.py`:
  all checks passed.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `npm --workspace @hallu-defense/sdk run typecheck`: passed.
- `npm --workspace @hallu-defense/sdk run test`: SDK 6 tests passed.
- `npm --workspace @hallu-defense/console run typecheck`: `next typegen` and `tsc`
  passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python -m pytest apps\api\tests\test_contracts.py -q`: 9 passed,
  1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 161 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 33 source
  files.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build
  passed.
- `make policy-test`, `make sandbox-test`, and `make evals-smoke`: attempted but
  failed because `make` is not installed on this Windows host.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: Python policy tests 23
  passed; `opa` was not on PATH, so the helper ran static Rego checks for 2 files.
- `.venv\Scripts\python -m pytest apps\api\tests -k sandbox -q`: 20 passed, 141
  deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; metrics written
  to `evals/reports/smoke-metrics.json`.
- `.venv\Scripts\python scripts\ci\check_grafana_dashboards.py`: validated 1 dashboard
  with 11 panels.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template`.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- The auth boundary is OIDC-ready but does not yet verify JWT signatures, issuer,
  audience, expiry, or JWKS in-process.
- `x-subject-id`, `x-roles`, and `x-tenant-id` must be treated as trusted gateway
  headers until full OIDC/JWT validation lands.
- A broader endpoint-to-role permission matrix is still pending.
- JSONL approval storage remains local-file persistence rather than distributed
  queue/database storage.

## 2026-07-08 - M5 trusted gateway signed auth claims

Slice selected:

- Continued the security hardening path after approval reviewer RBAC. The previous
  slice removed body-controlled reviewer identity, but `x-subject-id`, `x-roles`,
  and `x-tenant-id` were still unsigned boundary headers.
- Chose trusted gateway signed headers as the smallest production-aligned step that
  avoids adding a new cryptographic dependency while reducing header spoofing risk.

Implementation:

- Added auth configuration:
  - `HALLU_DEFENSE_AUTH_CLAIMS_MODE` with `unsigned_headers` and `signed_headers`.
  - `HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_SECRET_NAME`.
  - `HALLU_DEFENSE_AUTH_CLAIMS_SIGNATURE_TOLERANCE_SECONDS`.
- Added HMAC-SHA256 trusted-header signature helpers in `services/auth.py`.
- In `signed_headers` mode, `principal_from_headers()` now verifies:
  - `x-auth-claims-signature`,
  - `x-auth-claims-timestamp`,
  - tenant ID,
  - subject ID,
  - canonical sorted roles,
  - timestamp freshness.
- Wired FastAPI request context to resolve the signing key through `SecretManager`.
  Missing or inaccessible signing key fails closed with a 500 configuration error.
- Regenerated OpenAPI so every endpoint lists `x-auth-claims-signature` and
  `x-auth-claims-timestamp`.
- Updated `.env.example`, `docs/security/auth-rbac.md`, `SECURITY.md`, and
  `docs/TRACEABILITY_MATRIX.md`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_auth.py -q`: 9 passed.
- `.venv\Scripts\python -m pytest apps\api\tests\test_auth.py apps\api\tests\test_contracts.py apps\api\tests\test_core_flow.py -q`:
  69 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 166 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 33 source
  files.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build
  passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- `signed_headers` is trusted-gateway claim validation, not full in-process OIDC.
- JWT signature, issuer, audience, expiry, and JWKS validation remain future work.
- Tenant identity is still sourced from `x-tenant-id`; signed mode only protects that
  header from post-gateway tampering.
- A broader endpoint-to-role permission matrix is still pending.

## 2026-07-08 - M5 endpoint RBAC matrix

Slice selected:

- Continued the RBAC hardening path after signed gateway claims. The remaining
  immediate gap was that only approval decisions had endpoint-level role checks.
- Implemented this in the main agent because it touches security-sensitive FastAPI
  dependency wiring and authorization semantics.

Implementation:

- Added role constants for:
  - `admin`
  - `auditor`
  - `metrics_reader`
  - `policy_evaluator`
  - `rag_writer`
  - `sandbox_runner`
  - `tool_operator`
  - `verifier`
  - existing `approval_reviewer`
- Added `Principal.require_any_role()` and made `admin` satisfy specific role
  requirements.
- Added centralized `ENDPOINT_ROLE_REQUIREMENTS` in `api/dependencies.py`.
- Added `require_roles()` and `require_endpoint_roles()` FastAPI dependency helpers.
- Applied the matrix to metrics, claims, evidence retrieval, document ingestion,
  tool validation, policy evaluation, approval list/decision, sandbox, audit export,
  and verification run routes.
- Preserved local development compatibility when `HALLU_DEFENSE_AUTH_REQUIRED=false`.
  `POST /approvals/decide` remains stricter and always requires `approval_reviewer`.
- Updated `docs/security/auth-rbac.md`, `SECURITY.md`, and
  `docs/TRACEABILITY_MATRIX.md`.
- Regenerated `docs/api/openapi.yaml`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_auth.py -q`: 13 passed, 1
  FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests\test_auth.py apps\api\tests\test_contracts.py apps\api\tests\test_core_flow.py -q`:
  74 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 171 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 33 source
  files.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build
  passed.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: Python policy tests 23
  passed; `opa` was not on PATH, so the helper ran static Rego checks for 2 files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- RBAC roles are still carried by the authenticated principal; full JWT/JWKS role
  binding remains pending.
- The matrix is role-only. Richer ABAC rules for tenant, corpus, environment, and
  resource sensitivity remain future work.
- Local development still bypasses most endpoint roles when
  `HALLU_DEFENSE_AUTH_REQUIRED=false` to keep smoke/dev flows usable.

## 2026-07-08 - M5 auth/RBAC production config gate

Slice selected:

- Continued the enterprise hardening path after endpoint RBAC. Runtime roles existed,
  but production/staging could still be misconfigured with optional auth or unsigned
  claim headers.
- Chose a config gate plus runtime fail-closed validation because it prevents weak
  deployments without adding a new crypto/JWT dependency yet.

Implementation:

- Added `AuthConfigurationError` and `validate_auth_settings(settings)`.
- `load_settings()` now rejects production/staging when:
  - `HALLU_DEFENSE_AUTH_REQUIRED` is not true,
  - `HALLU_DEFENSE_AUTH_CLAIMS_MODE` is not `signed_headers`,
  - signed mode lacks a signing key reference,
  - signature tolerance is not positive.
- Added `infra/security/auth-policy.json` as the versioned auth/RBAC baseline.
- Added `scripts/ci/check_auth_config.py`, validating:
  - auth policy defaults,
  - `.env.example` auth keys,
  - `docs/security/auth-rbac.md` coverage,
  - production fail-closed snippets in `config.py`,
  - signed-headers and role matrix wiring,
  - Makefile target,
  - CI and security workflow wiring.
- Added `apps/api/tests/test_auth_config.py` with focused positive and negative tests.
- Wired `auth-config` into `Makefile`, `.github/workflows/ci.yml`, and
  `.github/workflows/security.yml`.
- Updated `SECURITY.md`, `docs/security/auth-rbac.md`, and
  `docs/TRACEABILITY_MATRIX.md`.

Validation:

- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python -m pytest apps\api\tests\test_auth_config.py -q`: 7 passed.
- `.venv\Scripts\python -m pytest apps\api\tests\test_auth_config.py apps\api\tests\test_auth.py -q`:
  21 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 178 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 33 source
  files.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated approval
  queue configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated encryption
  policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated RAG
  persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template`.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because it is
  not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console build
  passed.
- `git diff --check`: passed.

Remaining risks:

- The gate enforces trusted signed gateway claims in production-like environments,
  but full JWT/JWKS verification remains pending.
- It validates static artifacts and startup settings, not a deployed ingress or OIDC
  provider.
- Local development still defaults to `unsigned_headers` and optional auth for smoke
  compatibility.

## 2026-07-08 - M5 in-process OIDC JWT/JWKS validation

Slice selected:

- Continued the enterprise auth hardening path after the production config gate.
  The remaining gap was that production auth could rely on trusted gateway
  signed headers, but the API could not verify JWT signatures, issuer, audience,
  expiry, or JWKS in-process.
- Implemented in the main agent because the change touches security-sensitive
  request identity, production fail-closed config, and auth policy gates.

Implementation:

- Added `oidc_jwt` auth claims mode with config for issuer, audience, JWKS path,
  subject claim, roles claim, tenant claim, and clock skew.
- Added `services/oidc.py` with stdlib-only RS256 JWT validation:
  - strict three-segment JWT parsing,
  - `alg=RS256`,
  - required `kid`,
  - RSA signing key lookup from local JWKS,
  - PKCS#1 v1.5 SHA-256 signature verification,
  - issuer, audience, required `exp`, optional `nbf`/`iat`,
  - subject, roles, and tenant claim extraction.
- Wired `get_request_context()` so `oidc_jwt` derives the principal and tenant
  from the verified JWT and rejects a mismatching `x-tenant-id` header.
- Removed the attempted `cryptography` runtime dependency. Windows App Control
  blocked its native `_cffi_backend` DLL locally, so the final implementation
  avoids native crypto packages and was verified with `cryptography` absent.
- Updated `.env.example`, `docs/security/auth-rbac.md`, `SECURITY.md`,
  `infra/security/auth-policy.json`, `scripts/ci/check_auth_config.py`, and
  `docs/TRACEABILITY_MATRIX.md`.
- Updated the auth policy baseline so production requires `oidc_jwt`; trusted
  gateway `signed_headers` remains documented and fail-closed for deployments
  that verify OIDC before the API.

Validation issues found and fixed:

- First focused test collection failed because `cryptography` could not import
  `_cffi_backend` under Windows App Control. Fixed by replacing the dependency
  with stdlib RSA verification and pure-Python test signing helpers.
- `mypy` initially needed an explicit proof that required `exp` cannot be
  `None`; added a defensive check.
- Request-context OIDC tests initially used a fixture JWT expired relative to the
  real 2026 clock; updated only those integration tests to use a far-future
  expiry while keeping the expired-token unit test.
- `secret_scan.py` flagged a false positive in `oidc.py` for a local variable
  named `token`; renamed it without weakening the scanner.
- `python_dependency_audit.py` found vulnerable `cryptography 45.0.7` still
  installed from the abandoned attempt. Uninstalled it from the venv and
  reran the audit successfully.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_oidc_jwt.py apps\api\tests\test_auth_config.py apps\api\tests\test_auth.py -q`:
  29 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 186 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 34
  source files.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because
  it is not on PyPI.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated
  approval queue configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated
  encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated
  RAG persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template`.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python policy-related
  tests passed; `opa` was not on PATH, so static Rego checks ran for 2 files.
- `.venv\Scripts\python -m pytest apps\api\tests -k sandbox -q`: 20 passed, 166
  deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; metrics
  written to `evals/reports/smoke-metrics.json`.
- `.venv\Scripts\python scripts\ci\check_grafana_dashboards.py`: validated 1
  dashboard with 11 panels.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.
- `cryptography` import probe after uninstall: missing, confirming the OIDC
  tests no longer depend on the native package.

Remaining risks:

- `oidc_jwt` uses an explicitly configured local JWKS file; remote OIDC
  discovery, JWKS refresh/cache, and live provider metadata bootstrap remain
  pending.
- The RSA verifier is intentionally scoped to RS256. Additional algorithms must
  be explicitly designed, tested, and gated before use.
- Deployed identity-provider smoke tests are still pending.

## 2026-07-08 - M5 OIDC remote JWKS discovery and refresh cache

Slice selected:

- Continued the OIDC hardening path after local JWKS validation. The explicit
  remaining risk was that `oidc_jwt` only used a local JWKS file and could not
  support remote JWKS URL, OIDC discovery, cache TTL, or key rotation refresh.
- Kept the implementation stdlib-only and tested remote behavior with injected
  fetchers, so no external network or provider is required for local validation.

Implementation:

- Added OIDC settings and `.env.example` keys:
  - `HALLU_DEFENSE_OIDC_JWKS_URL`
  - `HALLU_DEFENSE_OIDC_DISCOVERY_URL`
  - `HALLU_DEFENSE_OIDC_JWKS_CACHE_TTL_SECONDS`
  - `HALLU_DEFENSE_OIDC_HTTP_TIMEOUT_SECONDS`
- Updated `validate_auth_settings()` so `oidc_jwt` accepts one of local JWKS
  path, direct JWKS URL, or explicit discovery URL. Production/staging reject
  insecure remote HTTP URLs.
- Added `OidcJwksResolver`:
  - local JWKS path loading remains supported,
  - remote JWKS URL fetches JSON with timeout and response-size limit,
  - discovery URL fetches and validates issuer plus `jwks_uri`,
  - remote JWKS is cached by TTL,
  - cache can be force-refreshed.
- Added `OidcJwksKeyNotFoundError` and wired `get_request_context()` to refresh
  JWKS once when a JWT presents an unknown `kid`, then retry validation.
- Updated `infra/security/auth-policy.json`, `scripts/ci/check_auth_config.py`,
  `docs/security/auth-rbac.md`, `SECURITY.md`, `docs/api/openapi.yaml`, and
  `docs/TRACEABILITY_MATRIX.md`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_oidc_jwt.py apps\api\tests\test_auth_config.py apps\api\tests\test_auth.py -q`:
  35 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 192 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 34
  source files.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because
  it is not on PyPI.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python policy-related
  tests passed; `opa` was not on PATH, so static Rego checks ran for 2 files.
- `.venv\Scripts\python -m pytest apps\api\tests -k sandbox -q`: 20 passed, 172
  deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; metrics
  written to `evals/reports/smoke-metrics.json`.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated
  approval queue configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated
  encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated
  RAG persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template`.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `.venv\Scripts\python scripts\ci\check_grafana_dashboards.py`: validated 1
  dashboard with 11 panels.
- `git diff --check`: passed.

Remaining risks:

- Tests mock remote JWKS/discovery fetches. A deployed identity-provider smoke
  test remains pending.
- JWKS cache is in-process memory; distributed deployments will refresh per API
  process unless a shared cache is introduced later.
- OIDC support remains intentionally RS256-only until additional algorithms are
  explicitly designed and gated.

## 2026-07-08 - M5 optional deployed OIDC provider smoke gate

Slice selected:

- Continued the OIDC hardening path after remote JWKS discovery and cache. The
  remaining gap was an executable gate that can validate a real deployed
  identity provider without making local CI depend on external network state.
- Kept the gate optional and fail-closed when enabled: local/CI runs skip unless
  explicit provider and short-lived JWT environment variables are supplied.

Implementation:

- Added `scripts/ci/oidc_provider_smoke.py`, which:
  - skips by default when `HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED` is not true,
  - requires issuer, audience, deployed JWKS/discovery source, and smoke JWT when
    enabled,
  - validates the same `oidc_jwt` settings gate used by the API,
  - force-refreshes JWKS/discovery before validating the supplied RS256 JWT,
  - optionally checks expected subject, expected tenant, and required role,
  - reports only pass/fail metadata and never prints the JWT or raw claims.
- Added smoke tests covering skip mode, required JWT, discovery-to-JWKS success,
  expected-subject mismatch, and insecure HTTP URL rejection.
- Wired the smoke into `Makefile`, `.github/workflows/ci.yml`,
  `.github/workflows/security.yml`, and `security-check`.
- Extended `check_auth_config.py` and `test_auth_config.py` so the auth gate
  validates smoke env keys, script snippets, Makefile target, CI wiring, and
  security workflow wiring.
- Added `apps/api/src/hallu_defense/py.typed` and package data metadata so the
  installed API package is visible to mypy when typechecking the standalone
  smoke script.
- Updated `.env.example`, `docs/security/auth-rbac.md`, `SECURITY.md`, and
  `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- The first focused validation found `check_auth_config.py` required SECURITY.md
  snippets for deployed-provider smoke documentation; added the missing security
  gap text.
- Ruff initially flagged E402 imports in the script after inserting `apps/api/src`
  into `sys.path`; added targeted `# noqa: E402` on the API imports.
- `mypy scripts/ci/oidc_provider_smoke.py` initially treated `hallu_defense` as
  untyped from the editable install; added the PEP 561 `py.typed` marker and
  package-data entry instead of suppressing the error.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_oidc_provider_smoke.py apps\api\tests\test_auth_config.py -q`:
  17 passed.
- `.venv\Scripts\python -m pytest apps\api\tests\test_oidc_provider_smoke.py -q`:
  5 passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 198 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 34
  source files.
- `.venv\Scripts\python -m mypy scripts\ci\oidc_provider_smoke.py`: passed with
  no issues in 1 source file.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\oidc_provider_smoke.py`: skipped because
  `HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED` is not true.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because
  it is not on PyPI.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python policy-related
  tests passed; `opa` was not on PATH, so static Rego checks ran for 2 files.
- `.venv\Scripts\python -m pytest apps\api\tests -k sandbox -q`: 20 passed, 178
  deselected, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; metrics
  written to `evals/reports/smoke-metrics.json`.
- `.venv\Scripts\python scripts\ci\check_grafana_dashboards.py`: validated 1
  dashboard with 11 panels.
- `.venv\Scripts\python scripts\ci\check_secrets_config.py`: validated
  Vault-compatible secrets configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated audit
  ledger configuration.
- `.venv\Scripts\python scripts\ci\check_approval_queue_config.py`: validated
  approval queue configuration.
- `.venv\Scripts\python scripts\ci\check_backup_retention_config.py`: validated
  backup/restore and retention policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_encryption_config.py`: validated
  encryption policy with 9 components.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated
  RAG persistence configuration.
- `.venv\Scripts\python scripts\dev\bootstrap_opensearch_template.py --dry-run`:
  returned dry-run JSON for `hallu_evidence_template`.
- `.venv\Scripts\python scripts\ci\check_container_scan_config.py`: validated
  container scan config for 2 images.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- Live deployed-provider smoke execution was not run locally because no provider
  URL/discovery endpoint and short-lived test JWT were supplied; local CI
  correctly exercises skip mode.
- The smoke validates one supplied short-lived JWT. It does not replace full
  deployed auth integration tests across every role/tenant combination.
- OIDC support remains intentionally RS256-only until additional algorithms are
  explicitly designed and gated.

## 2026-07-08 - M5 OIDC route tenant audit and role matrix

Slice selected:

- Continued the OIDC hardening path after the deployed-provider smoke gate. The
  next narrow gap was that unit tests proved JWT parsing and role extraction, but
  fewer tests proved the same identity through real FastAPI routes and HTTP audit
  middleware.
- Inspected `api/middleware.py` and found it derived audit tenant IDs from
  `x-tenant-id` before request dependencies could verify an `oidc_jwt` token.
  That meant a valid JWT request without the tenant header could execute under
  the token tenant while the HTTP audit event used `local-dev`.

Implementation:

- Changed `get_request_context()` to accept the FastAPI `Request` object and
  write `request.state.authenticated_tenant_id` after authentication succeeds.
- Changed `trace_and_audit_middleware()` to prefer the authenticated tenant from
  request state for `http_request` audit events, falling back to `x-tenant-id`
  or `local-dev` only when no authenticated context exists.
- Added `apps/api/tests/test_oidc_route_auth.py` with route-level tests proving:
  - `/verification/run` uses the JWT tenant in the response without
    `x-tenant-id`,
  - the HTTP audit event uses the verified JWT tenant,
  - verifier and auditor roles are enforced from JWT role claims on protected
    routes,
  - a mismatching `x-tenant-id` header is rejected with 401.
- Updated direct `get_request_context()` tests to pass a minimal Starlette
  `Request`, matching the new explicit dependency boundary.
- Documented the authenticated audit tenant behavior in
  `docs/security/auth-rbac.md`.
- Updated `docs/TRACEABILITY_MATRIX.md`.

Validation issues found and fixed:

- The first focused test run failed because existing direct unit tests called
  `get_request_context()` without a `Request`. Added minimal Starlette request
  helpers to those tests instead of weakening the new middleware contract.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_oidc_route_auth.py apps\api\tests\test_oidc_jwt.py apps\api\tests\test_auth.py -q`:
  27 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 201 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 34
  source files.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\oidc_provider_smoke.py`: skipped because
  `HALLU_DEFENSE_OIDC_PROVIDER_SMOKE_ENABLED` is not true.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python
  policy-related tests passed; `opa` was not on PATH, so static Rego checks ran
  for 2 files.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: no known
  vulnerabilities found; local editable `hallu-defense-api` was skipped because
  it is not on PyPI.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `git diff --check`: passed.

Remaining risks:

- Audit events for requests that fail before authenticated context exists still
  use the tenant header or `local-dev`; that is intentional because failed auth
  claims are not trusted.
- Live deployed-provider smoke execution still requires an external provider
  URL/discovery endpoint and short-lived test JWT.
- Richer ABAC conditions per resource/corpus/environment remain future work.

## 2026-07-08 - M5 RAG owner metadata ABAC guard

Slice selected:

- Continued enterprise hardening after OIDC/RBAC route tests. The next smallest
  security gap was RAG resource-level ABAC: persistent backends already filter
  by tenant, but ingestion and retrieval did not explicitly reject caller-supplied
  owner metadata for another tenant.

Implementation:

- Added `RagAccessPolicy` and `RagAccessDeniedError`.
- Stamped ingested documents with `owner_tenant_id` alongside `corpus_id`.
- Rejected `owner_tenant_id` or `tenant_id` metadata values that do not match
  the authenticated tenant on document ingestion and retrieval metadata filters.
- Mapped RAG access policy violations to HTTP 403 in `/documents/ingest` and
  `/evidence/retrieve`.
- Added tests proving cross-tenant owner metadata is rejected before indexing or
  persistent search, and that successful ingestion records owner metadata.
- Updated `docs/TRACEABILITY_MATRIX.md`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py -q`:
  18 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 35
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 204 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python
  policy-related tests passed; `opa` was not on PATH, so static Rego checks ran
  for 2 files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- Existing persisted RAG chunks created before this change may not have
  `owner_tenant_id`; backend tenant columns still enforce tenant isolation.
- ABAC is still scoped to tenant-owner metadata. Richer corpus-level grants,
  environment attributes, and admin delegation rules remain future work.
- `opa` is not installed on the local PATH, so local policy validation used the
  static Rego checker; CI can execute real OPA where installed.

## 2026-07-08 - M5 RAG corpus role metadata ABAC guard

Slice selected:

- Continued from tenant-owner RAG metadata enforcement into the next narrow ABAC
  gap: corpus-level authorization inside a tenant. The implementation keeps
  corpora tenant-scoped and does not introduce cross-tenant sharing.

Implementation:

- Extended `RagAccessPolicy` with reserved corpus metadata keys:
  - `corpus_id`
  - `corpus_reader_roles`
  - `corpus_writer_roles`
- Ingestion now rejects documents with conflicting `corpus_id` metadata and
  rejects `corpus_writer_roles` unless the authenticated principal has at least
  one required writer role. Successful ingestion still stamps `corpus_id` and
  `owner_tenant_id`.
- Retrieval now rejects inline documents that require missing
  `corpus_reader_roles` and filters persistent evidence chunks whose metadata
  requires reader roles the principal lacks. Claim evidence maps are filtered in
  step with returned evidence.
- Documented the RAG corpus metadata ABAC behavior in
  `docs/security/auth-rbac.md`.
- Updated `docs/TRACEABILITY_MATRIX.md`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_rag_index_adapters.py -q`:
  26 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 35
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 212 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 36 schemas,
  36 valid examples, 36 invalid examples, and 36 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python
  policy-related tests passed; `opa` was not on PATH, so static Rego checks ran
  for 2 files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote
  `docs/api/openapi.yaml`.
- `npm run test`: SDK 6, agent-adapters 5, and MCP 6 tests passed.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `git diff --check`: passed.

Remaining risks:

- Corpus grants are metadata-declared on indexed chunks, not a durable grant
  registry with lifecycle/audit APIs.
- Persistent searches still query tenant-scoped indexes first and then filter
  unreadable corpus-role hits at the API boundary.
- Existing persisted chunks may lack `corpus_reader_roles`, `corpus_writer_roles`,
  or `owner_tenant_id`; absence means open within the authenticated tenant.
- `opa` is not installed on the local PATH, so local policy validation used the
  static Rego checker; CI can execute real OPA where installed.

## 2026-07-08 - M5 durable RAG corpus grant registry

Slice selected:

- Continued the RAG ABAC hardening path after metadata-declared corpus reader
  and writer roles. The remaining gap was that corpus grants were only embedded
  in document metadata, with no durable tenant/corpus registry, no lifecycle API,
  and no public contract/SDK surface for operators.

Implementation:

- Added `CorpusGrant`, `CorpusGrantUpsertRequest`, `CorpusGrantListRequest`,
  `CorpusGrantResponse`, and `CorpusGrantListResponse` Pydantic contracts.
- Added `CorpusGrantRegistry` with:
  - in-memory local/test mode,
  - append-only JSONL persistence,
  - startup reload,
  - tenant/corpus keying,
  - created/updated attribution,
  - production/staging rejection of `memory`,
  - fail-closed handling of corrupt or unsupported records.
- Wired the registry into `RagAccessPolicy` so ingestion enforces durable writer
  roles and retrieval filters persistent evidence by durable reader roles when
  evidence metadata includes `corpus_id`.
- Added `POST /rag/corpus-grants/upsert` and
  `POST /rag/corpus-grants/list`; both require authenticated roles even when
  local auth is optional. Upsert writes an explicit `corpus_grant_upsert` audit
  event with role counts.
- Added TypeScript contracts, JSON Schemas, valid/invalid examples, SDK methods
  `upsertCorpusGrant()` and `listCorpusGrants()`, and SDK live API coverage.
- Updated `.env.example`, `docs/security/auth-rbac.md`,
  `docs/schemas/README.md`, `docs/TRACEABILITY_MATRIX.md`, and regenerated
  `docs/api/openapi.yaml`.

Validation issues found and fixed:

- Full API tests initially failed because
  `test_endpoint_role_matrix_covers_protected_routes` did not include the two
  new corpus grant endpoints. Fixed the test expectation to preserve exact RBAC
  matrix coverage.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_rag_index_adapters.py -q`:
  35 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 41 JSON
  schemas, 41 valid examples, 41 invalid examples, and 41 TypeScript interfaces.
- `.venv\Scripts\python -m pytest apps\api\tests\test_contracts.py -q`:
  9 passed, 1 FastAPI TestClient deprecation warning.
- `npm --workspace @hallu-defense/sdk run test`: SDK 7 tests passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 221 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python
  policy-related tests passed; `opa` was not on PATH, so static Rego checks ran
  for 2 files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 7, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; metrics
  written to `evals/reports/smoke-metrics.json`.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated
  RAG persistence configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated
  audit ledger configuration.
- `git diff --check`: passed.

Remaining risks:

- JSONL corpus grants are local append-only persistence. A deployed
  database/object-store-backed registry and migration plan remain future work.
- Registry reader enforcement for persistent evidence depends on chunks carrying
  `metadata.corpus_id`; older chunks without that metadata remain open within
  the authenticated tenant.
- No delete, disable, optimistic concurrency, or grant history query API exists
  yet.
- `opa` is not installed on the local PATH, so local policy validation used the
  static Rego checker; CI can execute real OPA where installed.

## 2026-07-08 - M5 RAG corpus grant lifecycle and pagination

Slice selected:

- Continued from the durable corpus grant registry. The next gap was grant
  lifecycle governance: operators could create/list grants, but could not
  disable them safely, list disabled grants intentionally, or page through the
  tenant grant set.

Implementation:

- Extended `CorpusGrant` with `version`, `disabled_by`, and `disabled_at`.
- Added `CorpusGrantDisableRequest` and `POST /rag/corpus-grants/disable`.
- Changed registry writes to keep append-only JSONL semantics:
  - upsert increments version and re-enables disabled grants,
  - disable increments version and records disabled attribution,
  - repeated disable of an already disabled grant is idempotent,
  - active `get()` ignores disabled grants, so disabled grants no longer enforce
    RAG reader/writer roles.
- Added cursor pagination to `CorpusGrantListRequest`/`CorpusGrantListResponse`
  with `include_disabled`, `limit`, `cursor`, and `next_cursor`.
- Added explicit `corpus_grant_disable` audit events.
- Updated Pydantic, TypeScript contracts, JSON Schemas, valid/invalid examples,
  SDK methods/tests, OpenAPI, auth/RBAC docs, schema docs, traceability matrix,
  and worklog.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py -q`:
  14 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 42 JSON
  schemas, 42 valid examples, 42 invalid examples, and 42 TypeScript interfaces.
- `.venv\Scripts\python -m pytest apps\api\tests\test_contracts.py apps\api\tests\test_auth.py apps\api\tests\test_corpus_grants.py -q`:
  37 passed, 1 FastAPI TestClient deprecation warning.
- `npm --workspace @hallu-defense/sdk run test`: SDK 7 tests passed.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 226 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 25 Python
  policy-related tests passed; `opa` was not on PATH, so static Rego checks ran
  for 2 files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server, and
  console.
- `npm run test`: SDK 7, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; metrics
  written to `evals/reports/smoke-metrics.json`.
- `npm audit --omit dev`: found 0 vulnerabilities.
- `.venv\Scripts\python scripts\ci\check_rag_persistence_config.py`: validated
  RAG persistence configuration.
- `.venv\Scripts\python scripts\ci\check_audit_ledger_config.py`: validated
  audit ledger configuration.
- `git diff --check`: passed.

Remaining risks:

- Corpus grant history is stored append-only but there is no public history
  query endpoint yet.
- No optimistic concurrency token is exposed for concurrent grant updates.
- JSONL remains local persistence; distributed database/object-store-backed
  grant storage remains future work.
- `opa` is not installed on the local PATH, so local policy validation used the
  static Rego checker; CI can execute real OPA where installed.

## 2026-07-08 - M5 corpus grants production config gate

Slice selected:

- Continued from corpus grant lifecycle and pagination. The next smallest gap was
  that audit ledger and approval queue persistence had explicit CI config gates,
  but the new corpus grant registry did not yet have an equivalent guard for env
  keys, fail-closed storage behavior, lifecycle docs, role matrix wiring, and
  CI/security workflow inclusion.

Implementation:

- Added `scripts/ci/check_corpus_grants_config.py`.
- Added focused positive and negative tests in
  `apps/api/tests/test_corpus_grants_config.py`.
- Added the `corpus-grants-config` Makefile target and included the validator in
  `security-check`.
- Wired the validator into both `.github/workflows/ci.yml` and
  `.github/workflows/security.yml`.
- Documented the gate in `docs/security/auth-rbac.md`.
- Updated traceability rows `FND-010`, `CI-008`, and added `CI-016`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants_config.py -q`:
  6 passed.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`:
  validated corpus grants configuration.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration after the docs/workflow update.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 232 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `git diff --check`: passed.

Review notes:

- `git status --short` still shows the repository tree as untracked, so git diff
  is not a reliable scope view on this host. Scope was reviewed with targeted
  `rg` output for `check_corpus_grants_config.py`, `corpus-grants-config`, and
  `CI-016`.

Remaining risks:

- The gate validates static local JSONL configuration and wiring. It does not
  prove deployed database/object-store corpus grant storage.
- Corpus grant history query and optimistic concurrency remain future slices.

## 2026-07-08 - M5 corpus grants optimistic concurrency

Slice selected:

- Continued from corpus grant lifecycle and the production config gate. The next
  documented governance gap was that grant mutations exposed a `version` in
  responses, but clients had no optional compare-and-set field to prevent stale
  authorization writes.

Implementation:

- Added optional `expected_version` to `CorpusGrantUpsertRequest` and
  `CorpusGrantDisableRequest`.
- Added `CorpusGrantVersionConflictError` and registry-side version checks:
  - `expected_version: 0` creates only when no current grant exists,
  - update/disable expected versions must match the current grant version,
  - stale mutations raise a domain conflict and do not append JSONL records,
  - omitting `expected_version` preserves backward-compatible behavior.
- Mapped stale upsert/disable mutations to HTTP `409 Conflict`.
- Added route and registry tests for stale upsert/disable conflicts.
- Updated TypeScript contracts, JSON Schemas, valid/invalid examples, SDK tests,
  OpenAPI, schema docs, RBAC docs, corpus grants config gate, traceability
  matrix, and worklog.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_corpus_grants_config.py -q`:
  23 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`:
  validated corpus grants configuration.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 42 JSON
  schemas, 42 valid examples, 42 invalid examples, and 42 TypeScript interfaces.
- `npm --workspace @hallu-defense/sdk run test`: SDK 7 tests passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests\test_contracts.py apps\api\tests\test_corpus_grants.py apps\api\tests\test_corpus_grants_config.py -q`:
  32 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 235 passed, 1 FastAPI
  TestClient deprecation warning.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server,
  and console.
- `npm run test`: SDK 7, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- Corpus grant history is still stored append-only but has no public history
  query API.
- JSONL remains local persistence; distributed database/object-store-backed
  grant storage remains future work.

## 2026-07-08 - M5 corpus grants history endpoint

Slice selected:

- Continued from optimistic concurrency. The next smallest governance gap was
  that grant revisions were written append-only, but operators could only see
  latest state through `/rag/corpus-grants/list`.

Implementation:

- Added `CorpusGrantHistoryRequest` and `CorpusGrantHistoryResponse`.
- Extended `CorpusGrantRegistry` with in-memory and JSONL-reloaded revision
  history. Upsert and non-idempotent disable mutations append revisions to the
  history list only after the JSONL append succeeds.
- Added `POST /rag/corpus-grants/history`, requiring `rag_writer` or `verifier`
  even when local auth is optional.
- Added tenant-scoped history pagination by `limit`/`cursor` and optional
  `corpus_id`, preserving append order.
- Added registry, route, cursor, RBAC matrix, contract, SDK unit, and SDK live
  coverage.
- Added TypeScript contracts, JSON Schemas, valid/invalid examples, SDK method
  `corpusGrantHistory()`, OpenAPI output, schema docs, RBAC docs, corpus grants
  config gate coverage, traceability, and worklog updates.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_auth.py apps\api\tests\test_contracts.py apps\api\tests\test_corpus_grants_config.py -q`:
  48 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 44 JSON
  schemas, 44 valid examples, 44 invalid examples, and 44 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`: validated
  corpus grants configuration.
- `npm --workspace @hallu-defense/sdk run test`: SDK 7 tests passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 237 passed, 1 FastAPI
  TestClient deprecation warning.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server,
  and console.
- `npm run test`: SDK 7, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- History exposes full revision snapshots, not diff summaries or actor/time
  filters beyond corpus and pagination.
- JSONL remains local persistence; distributed database/object-store-backed
  grant storage remains future work.

## 2026-07-08 - M5 corpus grants history filters

Slice selected:

- Continued from the corpus grants history endpoint. The next useful audit
  hardening was to make history queryable by actor and updated timestamp range
  instead of only tenant/corpus/cursor.

Implementation:

- Added `actor_id`, `updated_at_from`, and `updated_at_to` to
  `CorpusGrantHistoryRequest`.
- Applied history filters in `CorpusGrantRegistry.history_for_tenant()`:
  - `actor_id` matches the revision `updated_by`,
  - `updated_at_from` and `updated_at_to` bound revision `updated_at`,
  - all filters remain tenant-scoped before pagination.
- Added route-level validation for timezone-aware timestamp filters and ordered
  ranges, returning controlled `400` responses instead of internal errors.
- Updated JSON Schema, valid/invalid examples, TypeScript contracts, SDK unit
  and live tests, OpenAPI, docs, the corpus grants config gate, traceability,
  and worklog.

Validation issues found and fixed:

- The first test assumed distinct wall-clock timestamps, but the local runtime
  produced identical timestamps in rapid succession. Fixed the test with a
  deterministic `_now()` sequence.
- A Pydantic model-level range validator produced a `PydanticSerializationError`
  through the current validation error handler. Moved the check to explicit
  route validation so invalid ranges return `400` and never become `500`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_corpus_grants_config.py -q`:
  26 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 44 JSON
  schemas, 44 valid examples, 44 invalid examples, and 44 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`: validated
  corpus grants configuration.
- `npm --workspace @hallu-defense/sdk run test`: SDK 7 tests passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 238 passed, 1 FastAPI
  TestClient deprecation warning.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server,
  and console.
- `npm run test`: SDK 7, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.

Remaining risks:

- History exposes full revision snapshots, not diff summaries.
- JSONL remains local persistence; distributed database/object-store-backed
  grant storage remains future work.

## 2026-07-08 - M5 corpus grants history diff endpoint

Slice selected:

- Continued from actor/time-filtered corpus grant history. The next smallest
  audit hardening was to expose per-revision diff summaries so operators can see
  what changed without comparing full snapshots client-side.

Implementation:

- Added `CorpusGrantHistoryDiff`, `CorpusGrantHistoryDiffRequest`, and
  `CorpusGrantHistoryDiffResponse` Pydantic contracts.
- Added `CorpusGrantRegistry.history_diffs_for_tenant()`, which walks the
  tenant-scoped append-only history in order, computes each diff from the real
  previous revision before filters are applied, and then applies the same
  `corpus_id`, `actor_id`, timestamp, `limit`, and `cursor` filters as history.
- Added `POST /rag/corpus-grants/history/diff`, protected by `rag_writer` or
  `verifier` even when local auth is optional.
- Added TypeScript contracts, JSON Schemas, valid/invalid examples, SDK method
  `corpusGrantHistoryDiff()`, SDK unit and live API coverage, OpenAPI output,
  schema docs, RBAC docs, and corpus grants config gate coverage.
- Updated `docs/TRACEABILITY_MATRIX.md` for `CTR-022`, `CTR-025`, `API-011`,
  `API-020`, new `API-021`, `SEC-002`, `SEC-003`, `CI-003`, `CI-005`,
  `CI-006`, `CI-009`, and `CI-016`.

Validation issues found and fixed:

- `mypy` rejected `action` as an untyped `str` when constructing
  `CorpusGrantHistoryDiff`. Added shared Literal aliases for diff `action` and
  `changed_fields`, and typed the service-side variable accordingly.
- The first secret scan attempt used the wrong path,
  `scripts/security/secret_scan.py`, which does not exist. Re-ran the intended
  gate at `scripts/ci/secret_scan.py`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_auth.py apps\api\tests\test_contracts.py apps\api\tests\test_corpus_grants_config.py -q`:
  50 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 47 JSON
  schemas, 47 valid examples, 47 invalid examples, and 47 TypeScript interfaces.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`: validated
  corpus grants configuration.
- `npm --workspace @hallu-defense/sdk run test`: SDK 7 tests passed.
- `.venv\Scripts\python scripts\ci\export_openapi.py`: wrote updated
  `docs/api/openapi.yaml`.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: first failed on diff `action`
  typing, then passed with no issues in 36 source files after the Literal fix.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server,
  and console.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 239 passed, 1 FastAPI
  TestClient deprecation warning.
- `npm run test`: SDK 7, agent-adapters 5, and MCP 6 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `rg -n "/rag/corpus-grants/history/diff|CorpusGrantHistoryDiff" docs\api\openapi.yaml`:
  confirmed the path and schemas are present in OpenAPI.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\security\secret_scan.py`: failed because the
  file does not exist.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `npm audit --omit dev`: found 0 vulnerabilities.

Remaining risks:

- Diff summaries are derived from local append-only JSONL/in-memory history;
  distributed database/object-store-backed grant storage remains future work.
- The diff endpoint reports role and disabled-state changes only; richer
  semantic audit summaries can be added when grant metadata grows.

## 2026-07-08 - M5 corpus grants PostgreSQL storage adapter

Slice selected:

- Continued from corpus grant history/diff auditability. The repeated remaining
  risk was that corpus grant persistence was still local memory/JSONL only, so
  the next storage-hardening slice was an injectable PostgreSQL adapter plus a
  migration while preserving current local behavior.

Implementation:

- Added `infra/rag/pgvector/002_rag_corpus_grants.sql`, creating append-only
  `rag_corpus_grants` storage with tenant/corpus/version primary key,
  `sequence_id` replay order, JSONB payload, role columns, disabled-state
  consistency check, and tenant-oriented indexes.
- Added `CorpusGrantStorage`, `CorpusGrantSqlConnection`, and
  `PostgresCorpusGrantStorage`.
- Extended `CorpusGrantRegistry` to load/append through either JSONL or an
  injected storage adapter without changing endpoint behavior.
- Extended `create_corpus_grant_registry()` with a `postgres_connection`
  injection point for `HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=postgres`.
- Added `HALLU_DEFENSE_CORPUS_GRANTS_TABLE_NAME`, config-gate validation,
  focused tests for SQL parameterization, reload, fail-closed invalid payloads,
  unsafe table-name rejection, and factory behavior.
- Documented PostgreSQL corpus grant storage in `docs/security/auth-rbac.md`.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-008`, `CTR-025`, `API-017`,
  `SEC-002`, `SEC-003`, `CI-008`, and `CI-016`.

Validation issues found and fixed:

- `mypy` first rejected `_load_from_storage()` because the local variable
  `history` was defined in two branches. Renamed the injected-storage branch to
  `stored_history`; rerun passed.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_corpus_grants_config.py -q`:
  33 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`: validated
  corpus grants configuration, including PostgreSQL migration coverage.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: first failed on duplicate local
  variable naming, then passed with no issues in 36 source files after the fix.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 245 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_auth_config.py`: validated auth/RBAC
  configuration.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- The PostgreSQL adapter is intentionally driver-agnostic and requires an
  injected `CorpusGrantSqlConnection`; runtime driver/pool wiring remains a
  deployment integration slice.
- Local Docker/PostgreSQL migration execution is still unverified on this host
  because Docker is unavailable.

## 2026-07-08 - SEC-005 deterministic PII redaction for tool output

Slice selected:

- Advanced SEC-005 without touching the concurrent corpus grant persistence or
  TS-009 eval dashboard work. The smallest independent gap was that
  `/tools/validate-output` only redacted secret-like keys and did not detect
  common PII values.

Implementation:

- Extended `ToolSafetyService.validate_output()` to sanitize nested dict/list
  payloads.
- Preserved existing secret-like key precedence and `rewrite` behavior.
- Added deterministic, conservative PII redaction for:
  - email address values,
  - US-style SSNs with basic invalid-prefix rejection,
  - clearly formatted US phone numbers,
  - phone/email/SSN fields by key when the value is keyed as PII.
- Added regression tests for nested PII redaction and for preserving unlabeled
  plain numeric strings that should not be treated as phone numbers.
- Updated `SECURITY.md` and traceability rows `API-007`, `PY-010`, and
  `SEC-005`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_core_flow.py -q`:
  53 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\tool_safety.py apps\api\tests\test_core_flow.py`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 247 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts`:
  passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- PII detection is intentionally deterministic and conservative; it does not
  cover non-US identifiers, domain-specific sensitive values, or every phone
  notation.
- `ToolCallEnvelope` still uses `input` as the payload for output validation;
  a future public contract could add an explicit `output` field if API
  compatibility allows it.

## 2026-07-08 - TS-009 eval smoke dashboard from real report

Slice selected:

- Advanced TS-009 without adding backend surface. The smallest complete vertical
  slice was to make the existing eval smoke artifact visible in the console and
  typed through public contracts, using `evals/reports/smoke-metrics.json`
  directly instead of mock data.

Implementation:

- Added `EvalSmokeMetrics`, `EvalSmokeScenarioResult`, and `EvalSmokeReport`
  TypeScript contracts plus JSON Schemas and valid/invalid examples.
- Added a server-side console report loader for
  `evals/reports/smoke-metrics.json` with defensive shape validation and no
  synthetic fallback data.
- Updated the Next console page to load the real eval smoke report and render an
  eval dashboard with scenario count, passed scenarios, p95 latency, cost,
  accuracy, unsupported recall, groundedness, faithfulness, false-positive
  blocking, critical pass-through, and per-scenario outcomes.
- Added console Vitest coverage that loads the real report artifact and rejects
  malformed payloads.
- Updated schema docs and contract schema coverage.

Validation issues found and fixed:

- Initial console typecheck/build failed because `Number.isInteger()` did not
  narrow an `unknown` value for a later comparison. Fixed the parser with an
  explicit `typeof scenarioCount === "number"` guard.

Validation:

- `npm --workspace @hallu-defense/console run test`: 2 passed.
- `npm --workspace @hallu-defense/contracts run typecheck`: passed.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 50 JSON
  schemas, 50 valid examples, 50 invalid examples, and 50 TypeScript
  interfaces.
- `npm --workspace @hallu-defense/console run typecheck`: first failed on the
  `unknown` narrowing issue, then passed after the fix.
- `npm --workspace @hallu-defense/console run build`: first failed on the same
  type issue, then passed after the fix.
- `.venv\Scripts\python -m pytest apps\api\tests\test_contracts.py -q`:
  9 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python evals\runners\smoke.py`: 2 scenarios passed; report
  regenerated with final decision accuracy 1.0, trace coverage 1.0, claim and
  verdict ledger coverage 1.0, false-positive blocking 0.0, critical
  pass-through 0.0, and p95 latency 58.056 ms.
- `npm run typecheck`: passed for contracts, SDK, agent-adapters, MCP server,
  and console.
- `npm run test`: SDK 7, agent-adapters 5, MCP 6, and console 2 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and Next console
  build passed.
- `.venv\Scripts\python -m ruff check apps\api\tests\test_contracts.py`:
  passed.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- The dashboard is static/offline over the latest smoke report artifact; no live
  eval metrics API, historical trend storage, or multi-run comparison exists
  yet.
- The smoke set still has only 2 scenarios, so the dashboard proves wiring and
  contract discipline but not broad eval quality.

## 2026-07-08 - M5 corpus grants PostgreSQL runtime DSN wiring

Slice selected:

- Continued from the PostgreSQL corpus grant storage adapter. The smallest
  remaining deployment gap was that `postgres` backend mode still required an
  injected SQL connection, so a configured deployment could not create the
  default PostgreSQL grant registry from settings alone.

Coordination:

- Attempted to delegate a larger parallel slice to Claude/Fable before
  continuing locally. The direct Claude Code MCP `Agent` path failed because
  this installation exposes no `general-purpose` agent type. A Claude CLI
  process was launched with `--model fable --effort max` against
  `C:\Users\Estudiante-10\Documents\claude-fable-hallu-defense-work`, but it
  produced no output or diffs and was stopped after a working MCP route was
  available.
- Launched a Claude Code `Workflow` with `model: "fable"` and `effort: "max"`.
  The workflow transcript proved it was running `claude-fable-5`, but the MCP
  sandbox blocked access to the external copy. To keep Fable isolated while
  staying inside the allowed workspace, created
  `.codex-fable-work` with its own git repository, branch
  `fable5/eval-expansion`, and baseline commit
  `7e5faf4 baseline for fable isolated work`, then resumed the Fable workflow
  with that path. Fable is working there asynchronously; its changes are not
  integrated until Codex inspects and validates them.

Implementation:

- Added runtime setting `HALLU_DEFENSE_POSTGRES_DSN`.
- Added `psycopg[binary]` as an API runtime dependency.
- Added `PsycopgCorpusGrantSqlConnection`, a lazy psycopg-backed
  `CorpusGrantSqlConnection` wrapper that opens connections with `dict_row`,
  executes parameterized SQL, and returns mapping rows to the existing
  append-only `PostgresCorpusGrantStorage`.
- Updated `create_corpus_grant_registry()` so
  `HALLU_DEFENSE_CORPUS_GRANTS_BACKEND=postgres` uses an injected SQL
  connection when supplied, otherwise creates the psycopg connection from
  `HALLU_DEFENSE_POSTGRES_DSN`, and fails closed when neither exists.
- Documented the DSN path in `.env.example` and `docs/security/auth-rbac.md`.
- Updated the corpus grants config gate to require the DSN setting, psycopg
  wrapper, and pooling guidance.
- Updated `docs/TRACEABILITY_MATRIX.md` for `CTR-025`, `API-017`, `SEC-002`,
  `CI-008`, and `CI-016`.

Validation:

- `.venv\Scripts\python -c "import psycopg; print(psycopg.__version__)"`:
  printed `3.3.4`.
- `.venv\Scripts\python -m pytest apps\api\tests\test_corpus_grants.py apps\api\tests\test_corpus_grants_config.py -q`:
  35 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\check_corpus_grants_config.py`: validated
  corpus grants configuration.
- `.venv\Scripts\python scripts\ci\python_dependency_audit.py`: skipped local
  package `hallu-defense-api` because it is not on PyPI; no known
  vulnerabilities found.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\corpus_grants.py apps\api\src\hallu_defense\config.py apps\api\src\hallu_defense\services\__init__.py apps\api\tests\test_corpus_grants.py scripts\ci\check_corpus_grants_config.py`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 249 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- The default psycopg path opens a fresh connection per execute/fetch call.
  High-throughput deployments should inject a pooled adapter.
- Local Docker/PostgreSQL migration execution is still unverified on this host
  because Docker is unavailable.
- The Claude/Fable workflow is running asynchronously in `.codex-fable-work`;
  no Fable changes have been inspected or integrated yet.

## 2026-07-08 - M1 claim endpoint behavior coverage

Slice selected:

- Continued API discipline without overlapping the Fable eval-expansion work.
  The traceability matrix still listed `/claims/extract`,
  `/claims/classify`, `/claims/verify`, and `/response/repair` as implemented
  but not endpoint-behavior tested.

Coordination:

- Rechecked `.codex-fable-work`; no Fable diff was present before this slice.
  Fable's transcript shows its own command sandbox is denying shell/git commands
  against `.codex-fable-work`, so Codex will keep verifying that copy from the
  main session before any integration.

Implementation:

- Added endpoint tests proving:
  - `/claims/extract` returns deterministic atomic claim IDs and source spans
    tied to the request `message_id`.
  - `/claims/classify` marks repo-state, test-result, and opinion claims with
    expected risk and `requires_evidence` behavior.
  - `/claims/verify` surfaces contradictory document evidence as a typed
    `CONTRADICTED` verdict with supporting and contradicting evidence IDs.
  - `/response/repair` preserves supported claims with citations, removes
    unsupported claims, records repaired claim IDs, and returns
    `final_decision=repaired`.
- Added `.codex-fable-work/` to `.gitignore` so the auxiliary Fable copy cannot
  be accidentally included in product changes.
- Updated `docs/TRACEABILITY_MATRIX.md` for `API-001`, `API-002`, `API-004`,
  `API-005`, and `CI-003`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_core_flow.py -q`:
  57 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\tests\test_core_flow.py`:
  passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 253 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.
- `git check-ignore -v .codex-fable-work`: confirmed `.gitignore` ignores the
  auxiliary Fable copy.

Remaining risks:

- Claim extraction/classification/verification remain deterministic local
  implementations; richer semantic extraction, classification, and
  contradiction detection remain future hardening.
- Fable has not yet produced an inspectable diff to integrate.

## 2026-07-08 - M5 expanded offline eval scenarios

Slice selected:

- Continued from the Fable delegation attempt. Fable produced a useful eval
  expansion design but no writable diff in `.codex-fable-work`, so Codex
  implemented the smallest verified subset locally: an offline scenario runner
  covering documents, code-agent claims, tool safety, and sandbox abuse.

Coordination:

- Rechecked `.codex-fable-work`; `git status --short` was empty, so there was
  no Fable patch to integrate.
- Kept the Fable copy ignored in the product worktree and updated the local
  secret scanner to skip the auxiliary ignored copy.

Implementation:

- Added `evals/golden_sets/scenarios.json` with 9 deterministic scenarios:
  partially false document answers, contradictory document sources, a false
  test-result claim without command evidence, invalid tool input, high-risk
  tool approval, secret redaction, sandbox path traversal, destructive command
  abuse, and denied-network abuse.
- Added `evals/runners/scenarios.py`, which drives the FastAPI app through
  `TestClient`, validates tool pre/post checks, exercises `SandboxRunner` in a
  temporary workspace, computes category and safety metrics, and writes
  `evals/reports/scenario-metrics.json`.
- Added API tests for scenario coverage and deterministic metrics.
- Wired the expanded scenario runner into `Makefile` and
  `.github/workflows/evals.yml`.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-011`, `EVAL-001`,
  `EVAL-002`, `CI-003`, `CI-006`, and `CI-008`.

Validation:

- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and
  wrote `evals/reports/smoke-metrics.json`; p95 latency 56.191 ms.
- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 9 scenarios
  and wrote `evals/reports/scenario-metrics.json`; pass rate 1.0,
  verification decision accuracy 1.0, high-risk approval block rate 1.0,
  secret redaction rate 1.0, sandbox block rate 1.0, p95 latency 59.214 ms.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 255 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 50 JSON
  schema files, 50 valid examples, 50 invalid examples, and 50 TypeScript
  interfaces.
- `git diff --check`: passed.
- `git -C .codex-fable-work status --short`: empty output.
- `make evals-scenarios`: failed because `make` is not installed on this host;
  the underlying runner command passed directly through the virtualenv Python.

Remaining risks:

- Expanded eval metrics are still offline JSON artifacts; there is no trend
  storage or console visualization for the 9-scenario runner yet.
- The new scenarios do not yet cover direct/indirect prompt injection, data
  poisoning, contradictory tool outputs, or deeper semantic implementation
  claims.
- `make` targets cannot be executed directly on this Windows host until a make
  executable is installed.

## 2026-07-08 - M5 adversarial policy eval coverage

Slice selected:

- Continued M5 eval hardening by closing the explicit adversarial gaps left in
  the expanded scenario set: direct prompt injection, indirect prompt
  injection, data poisoning, and contradictory tool output policy handling.

Implementation:

- Added deterministic Python policy rules that block direct prompt injection,
  block indirect prompt injection from retrieved/tool-provided content, and
  block poisoned/tampered evidence before verification uses it.
- Synced the formal Rego baseline with matching blocking rules and Rego tests.
- Extended `evals/runners/scenarios.py` with `policy_evaluate` scenarios that
  call `/policy/evaluate` through the FastAPI app and assert trace presence,
  actions, and matched policy rules.
- Expanded `evals/golden_sets/scenarios.json` from 9 to 13 scenarios by adding
  contradictory tool output, direct prompt injection, indirect prompt
  injection, and data poisoning cases.
- Added API policy tests and eval metric assertions for prompt-injection block
  rate, data-poisoning block rate, and contradictory-tool-output guard rate.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-011`, `API-008`, new
  `SEC-013`, `EVAL-001`, `EVAL-002`, `CI-003`, and `CI-007`.

Validation:

- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 13 scenarios
  and wrote `evals/reports/scenario-metrics.json`; pass rate 1.0,
  prompt-injection block rate 1.0, data-poisoning block rate 1.0,
  tool-contradiction guard rate 1.0, p95 latency 66.621 ms.
- `.venv\Scripts\python -m pytest apps\api\tests\test_eval_scenarios.py -q`:
  2 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m pytest apps\api\tests\test_core_flow.py -q`: 61
  passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 29 Python
  policy/config tests passed; `opa` was not found on PATH, so the runner used
  `check_rego_policy.py`, which passed static Rego checks for 2 files.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 36
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 259 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and
  wrote `evals/reports/smoke-metrics.json`; p95 latency 66.258 ms.
- `git diff --check`: passed.
- `git -C .codex-fable-work status --short`: empty output.

Remaining risks:

- Prompt-injection and data-poisoning policy enforcement currently depends on
  explicit upstream attributes; content-level detectors/classifiers for those
  attributes remain future work.
- Local Rego validation is static because the `opa` executable is not available
  on this host.
- Expanded eval metrics are still offline JSON artifacts without trend storage
  or console visualization.

## 2026-07-08 - M5 content security scanner integration

Slice selected:

- Continued from `SEC-013`. The previous slice blocked prompt injection and
  data poisoning only when upstream code supplied explicit policy attributes.
  The next vertical slice was to detect concrete malicious content and block it
  before verification uses contaminated input or evidence.

Implementation:

- Added `ContentSecurityScanner`, a deterministic scanner for:
  - direct user-message prompt injection,
  - indirect instructions in retrieved documents/tool outputs,
  - data poisoning and retrieval override markers.
- Wired `HybridRetriever` so document chunks are marked with
  `structured_content.security.threats` before they can be returned as
  evidence.
- Wired `VerificationOrchestrator` to:
  - scan user input after claim classification and block direct prompt
    injection before retrieval,
  - scan tool outputs and retrieved evidence before claim verification,
  - feed threat attributes into `PolicyEngine`,
  - return an auditable blocked `VerificationRun` with claim/verdict/evidence
    ledgers and policy rule IDs.
- Reused a shared scanner instance in API dependencies for retriever and
  orchestrator.
- Expanded scenario evals from 13 to 16 cases with content-level direct prompt
  injection, indirect prompt injection in documents, and data-poisoning
  document attacks.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-011`, `SEC-013`, `EVAL-001`,
  `EVAL-002`, `CI-002`, and `CI-003`.

Validation:

- `.venv\Scripts\python -m pytest apps\api\tests\test_core_flow.py -q`: 65
  passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\content_security.py apps\api\src\hallu_defense\services\orchestrator.py apps\api\src\hallu_defense\services\retrieval.py apps\api\src\hallu_defense\api\dependencies.py apps\api\tests\test_core_flow.py`:
  all checks passed.
- Initial `.venv\Scripts\python -m mypy apps\api\src` found 3 typing errors in
  `content_security.py`; fixed the metadata typing and literal casts.
- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 16 scenarios
  and wrote `evals/reports/scenario-metrics.json`; pass rate 1.0,
  prompt-injection block rate 1.0, data-poisoning block rate 1.0,
  tool-contradiction guard rate 1.0, p95 latency 56.303 ms.
- `.venv\Scripts\python -m pytest apps\api\tests\test_eval_scenarios.py -q`:
  2 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 263 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python scripts\ci\run_policy_tests.py`: 29 Python
  policy/config tests passed; `opa` was not found on PATH, so the runner used
  `check_rego_policy.py`, which passed static Rego checks for 2 files.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and
  wrote `evals/reports/smoke-metrics.json`; p95 latency 57.886 ms.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.
- `git -C .codex-fable-work status --short`: empty output.

Remaining risks:

- The scanner is intentionally deterministic and conservative; adversaries can
  evade the current regex patterns, so broader classifiers/calibration remain
  future work.
- Local Rego validation is still static because the `opa` executable is not
  installed on this host.
- Expanded eval metrics are still offline JSON artifacts without trend storage
  or console visualization.

## 2026-07-08 - M5 false repo claim eval coverage

Slice selected:

- Continued M5 eval hardening by closing the explicit gap for false repository
  file/function claims in the expanded offline scenario set.

Implementation:

- Expanded `evals/golden_sets/scenarios.json` from 16 to 18 scenarios with:
  - a false file-existence claim contradicted by `sandbox_inspection.v1`
    static file inventory,
  - a false function-existence claim contradicted by `sandbox_inspection.v1`
    static symbol inventory.
- Added `repo_false_claim_block_rate` to `evals/runners/scenarios.py`.
- Updated `apps/api/tests/test_eval_scenarios.py` to require both new scenario
  IDs, 18 deterministic scenarios, and `repo_false_claim_block_rate=1.0`.
- Fixed `ClaimExtractor` sentence splitting so repository paths such as
  `missing.py` and `service.py` are preserved instead of being truncated at the
  extension dot.
- Added a regression test proving `/claims/extract` preserves repository file
  extensions and source spans.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-011`, `API-001`, `SBOX-009`,
  `EVAL-001`, `EVAL-002`, and `CI-003`.

Validation:

- Initial `.venv\Scripts\python evals\runners\scenarios.py` failed for the two
  new scenarios because extracted claims were truncated to `missing`/`service`,
  producing `NOT_FOUND`/`abstain` instead of `CONTRADICTED`/`block`.
- Initial `.venv\Scripts\python -m pytest apps\api\tests\test_eval_scenarios.py -q`
  failed with `pass_rate=0.888889` for the same root cause.
- `.venv\Scripts\python -m ruff check evals\runners\scenarios.py apps\api\tests\test_eval_scenarios.py`:
  all checks passed.
- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 18 scenarios
  and wrote `evals/reports/scenario-metrics.json`; pass rate 1.0,
  verification decision accuracy 1.0, repo false-claim block rate 1.0, p95
  latency 56.54 ms.
- `.venv\Scripts\python -m pytest apps\api\tests\test_eval_scenarios.py apps\api\tests\test_core_flow.py::test_claim_extraction_preserves_repository_file_extensions -q`:
  3 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src\hallu_defense\services\claim_extractor.py apps\api\tests\test_core_flow.py evals\runners\scenarios.py apps\api\tests\test_eval_scenarios.py`:
  all checks passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 264 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and
  wrote `evals/reports/smoke-metrics.json`; p95 latency 55.383 ms.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- The new repo evals cover deterministic file/symbol absence, not arbitrary
  semantic implementation correctness.
- Expanded eval metrics are still offline JSON artifacts without trend storage
  or console visualization.

## 2026-07-08 - M5 semantic repo implementation eval coverage

Slice selected:

- Continued M5 eval hardening by moving existing deterministic repository
  implementation/fix claim checks from unit-level coverage into the expanded
  `/verification/run` scenario runner.

Coordination:

- Attempted to launch a Claude Code/Fable audit agent through the available
  MCP tool. The call failed because the session reported no available agent
  types (`general-purpose` was not found and the available-agent list was
  empty), so no Fable diff was produced or integrated.
- Kept edits local and limited to eval scenarios, metrics, tests, and docs.

Implementation:

- Expanded `evals/golden_sets/scenarios.json` from 18 to 21 scenarios with:
  - a blocked semantic implementation claim where `service.ts` changed but
    added lines do not prove the asserted `cache` behavior,
  - a blocked fix claim where a successful command exists but is broad and does
    not target the claimed file/symbol/behavior,
  - a supported fix claim where `sandbox_inspection.v1` changed-line evidence
    and `sandbox_command.v1` targeted command metadata both support the claim.
- Added `repo_semantic_claim_decision_accuracy` to
  `evals/runners/scenarios.py`.
- Updated `apps/api/tests/test_eval_scenarios.py` to require the three new
  scenario IDs, `scenario_count=21`, and semantic repo decision accuracy 1.0.
- Updated `docs/TRACEABILITY_MATRIX.md` for `FND-011`, `SBOX-012`,
  `SBOX-013`, `SBOX-014`, `SBOX-015`, `EVAL-001`, and `EVAL-002`.

Validation:

- `.venv\Scripts\python evals\runners\scenarios.py`: passed for 21 scenarios
  and wrote `evals/reports/scenario-metrics.json`; pass rate 1.0,
  verification decision accuracy 1.0, repo false-claim block rate 1.0,
  repo semantic-claim decision accuracy 1.0, p95 latency 4.42 ms.
- `.venv\Scripts\python -m pytest apps\api\tests\test_eval_scenarios.py -q`:
  2 passed, 1 FastAPI TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check evals\runners\scenarios.py apps\api\tests\test_eval_scenarios.py`:
  all checks passed.
- `.venv\Scripts\python -m pytest apps\api\tests -q`: 264 passed, 1 FastAPI
  TestClient deprecation warning.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  all checks passed.
- `.venv\Scripts\python -m mypy apps\api\src`: passed with no issues in 37
  source files.
- `.venv\Scripts\python evals\runners\smoke.py`: passed for 2 scenarios and
  wrote `evals/reports/smoke-metrics.json`; p95 latency 53.954 ms.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.

Remaining risks:

- Semantic implementation verification is still deterministic term/target
  matching. It does not prove arbitrary behavioral correctness beyond the
  changed-line and targeted-command evidence available to the verifier.
- Expanded eval metrics remain offline JSON artifacts without trend storage or
  console visualization.

## 2026-07-08 - TS-009 expanded scenario eval dashboard

Slice selected:

- Continued M5 eval observability by making the expanded 21-scenario offline
  eval metrics visible in the Next.js console instead of leaving them only as
  JSON artifacts.

Implementation:

- Added public TypeScript contracts plus JSON Schemas and valid/invalid
  examples for:
  - `EvalScenarioMetrics`,
  - `EvalScenarioResult`,
  - `EvalScenarioReport`.
- Extended the console eval report loader to read both:
  - `evals/reports/smoke-metrics.json`,
  - `evals/reports/scenario-metrics.json`.
- Added strict parser checks for expanded scenario metrics, including
  scenario count, passed count, rate bounds, category pass-rate shape, and
  per-scenario result shape.
- Updated the console dashboard to render a second eval panel with expanded
  scenario pass rate, category rates, repo false-claim guard rate, repo
  semantic-claim accuracy, sandbox block rate, p95 latency, and per-scenario
  pass/fail outcomes.
- Updated console tests to load the real expanded scenario report artifact and
  reject malformed expanded report payloads.
- Updated `docs/schemas/README.md` and `docs/TRACEABILITY_MATRIX.md` for
  `CTR-022`, `TS-009`, `EVAL-002`, `CI-004`, and `CI-006`.

Validation:

- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: validated 53 JSON
  schema files, 53 valid examples, 53 invalid examples, and 53 TypeScript
  interfaces.
- `npm --workspace @hallu-defense/console run test`: 4 console eval-report
  tests passed.
- `npm --workspace @hallu-defense/console run typecheck`: `next typegen` and
  `tsc --noEmit` passed.
- `npm run typecheck`: all TypeScript workspaces passed.
- `npm run test`: SDK 7 tests passed, agent-adapters 5 tests passed,
  MCP server 6 tests passed, console 4 tests passed.
- `npm run build`: contracts, SDK, agent-adapters, MCP server, and console
  production build passed; Next.js prerendered `/` and `/_not-found`.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: passed.
- Attempted to start another console dev server on port 3001; Next.js detected
  an existing console dev server on `http://localhost:3000` and rejected the
  duplicate process. `Invoke-WebRequest http://127.0.0.1:3000` returned HTTP
  200 and the rendered HTML contained the `Eval scenarios` marker.

Remaining risks:

- The dashboard is still a static/offline view over the latest local report
  files. Historical trend storage, multi-run comparison, and live metrics API
  ingestion remain future work.
