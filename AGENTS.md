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

## Persistent Six-Thread Orchestration Workflow

When the user asks to apply the six-front parallel workflow, preserve and reuse this operating model:

1. Inspect the repository, run a pre-check, and create one explicit checkpoint commit on the integration branch. A checkpoint may be labeled work-in-progress, but its validation state must never be overstated.
2. Deconstruct the remaining work into exactly six bounded, non-overlapping fronts and create six fresh Codex conversations from the same checkpoint.
3. Give every conversation its own worktree and branch. Never let a secondary leader edit the root worktree, `master`, another leader's branch, or shared persistent infrastructure.
4. Use `gpt-5.6-sol` with `ultra` reasoning for the six secondary leaders when that model and effort are available.
5. Each secondary leader must use the available multi-agent capacity continuously when parallel work exists, targeting six subagents per thread. At most three subagents may write code at once; use the remaining capacity for tests, review, threat modeling, and independent audit. Actual platform concurrency limits still apply.
6. Every leader owns one front end to end: implementation, tests, deterministic validation, documentation, traceability, and worklog updates. It must self-audit the completed diff, fix every finding it can reproduce, and repeat validation before handoff.
7. Every handoff must include the branch, commit SHA, changed files, exact commands and results, remaining risks, and the self-audit outcome. Leaders must not merge, cherry-pick, push, or claim global completion.
8. The root agent remains the sole orchestrator and final decision-maker: monitor leaders, challenge unsupported claims, inspect every diff, reject or selectively integrate commits, resolve overlaps, and rerun proportional validation.
9. Run the global quality gates and safe scratch-only live tests after integration. Update `docs/TRACEABILITY_MATRIX.md` and `docs/WORKLOG.md` with reproducible evidence.
10. Merge the integration branch into `master` only after the final independent audit is clean. Never use destructive Git operations, weaken tests or security defaults, or touch persistent user data to force completion.

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
