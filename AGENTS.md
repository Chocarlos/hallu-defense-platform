# AGENTS.md

This repository is an enterprise anti-hallucination platform for LLMs and agents. Agents working here must optimize for verifiable progress, not plausible summaries.

## Required Working Loop

1. Read `AGENTS.md`, `docs/PLAN_MASTER.md`, `docs/TRACEABILITY_MATRIX.md`, and `docs/WORKLOG.md`.
2. Inspect the current repository state before relying on memory.
3. Pick the next smallest vertical slice that advances the full product.
4. Update the plan when the change is multi-step.
5. Implement the change with tests.
6. Run relevant validation commands.
7. Fix root causes when validation fails.
8. Update `docs/TRACEABILITY_MATRIX.md` and `docs/WORKLOG.md`.
9. Report evidence, risks, and the next recommended slice.

## Non-Negotiable Rules

- Do not claim tests, builds, files, functions, diffs, or repository state without deterministic evidence.
- Do not mark a requirement as `accepted` without implementation, tests, docs, and recorded evidence.
- Do not allow high-risk tool calls without approval support.
- Do not mark repository/test/build claims as supported without `SandboxRun` or command evidence.
- Do not mix tenants or retrieve evidence across tenants.
- Do not log secrets or sensitive payloads.
- Do not call external LLM providers directly from business logic; use provider adapters.
- Do not weaken security defaults to make tests pass.
- Do not delete or weaken tests to make validation green.

## Current Architecture

- `apps/api`: Python 3.12 FastAPI verification plane.
- `packages/contracts`: TypeScript public contracts and JSON Schemas.
- `packages/sdk`: TypeScript SDK.
- `packages/mcp-server`: JSON-RPC/MCP-compatible server wrapper.
- `apps/console`: Next.js DevEx console.
- `infra`: local and future deployment infrastructure.
- `evals`: golden sets, scenarios, runners, and reports.

## Standard Commands

Use the `Makefile` commands when available:

- `make lint`
- `make typecheck`
- `make test`
- `make build`
- `make contracts`
- `make openapi`
- `make policy-test`
- `make sandbox-test`
- `make evals-smoke`
- `make security-check`

