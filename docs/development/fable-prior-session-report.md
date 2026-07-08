# Fable Prior Session Report

This report captures the previous-session context supplied by the user. Fable
must understand it before receiving implementation work, but must also verify
the current repository state because later work may have superseded parts of
the report.

## Executive Summary

Two real product slices were advanced:

1. RAG structural retrieval: Markdown section chunking was added so evidence can
   preserve verifiable document structure.
2. Eval history and console trends: persistent scenario history, public
   contracts, payload validation, and Next.js trend visualization were added.

Claude/Fable delegation was attempted but did not produce an integrable diff in
that session. Its work was treated as auxiliary and untrusted.

## Fable / Claude Coordination From That Session

- Direct `claude_code.Agent` launch with model `fable`, worktree isolation, and
  automatic mode failed because the general-purpose agent was unavailable.
- `claude_code.Workflow` launched, but worktree creation failed with:
  `Failed to resolve base branch "HEAD": git rev-parse failed`.
- The cause was verified: the repository was initialized as Git but had no valid
  `HEAD`; files appeared as untracked and there was no commit base for normal
  branches or worktrees.
- A fallback copy was created at `.claude-fable-work/scenario-history`.
- Fable was launched in that copy without worktree isolation and instructed to
  work only there.
- Fable could read files and move through the repo but became blocked by command
  approvals.
- Fable left no final complete report and no branch/diff that could be
  integrated.
- Result: no Fable output from that session was merged.

Current status superseding that blocker:

- The missing `HEAD` blocker has since been fixed with baseline commit
  `8dec1b3`.
- The current Fable delegation workflow is `.claude/workflows/fable-delegate.js`.
- The current supported route is Claude Code `Workflow` with `model: "fable"`
  and git worktree isolation.
- Direct `mcp__claude_code.Agent` still reports no registered local agent types
  in this session, so it remains unsupported here.

## Product Work Completed In That Session

### RAG: Structural Markdown Chunking

The retrieval service was changed so documents with Markdown headings
(`#`, `##`, and so on) are chunked by section rather than treated only as flat
paragraphs.

The goal was to keep structural context attached to evidence. Evidence should
not only say "this text appeared"; it should also say "this text belongs to this
section of the document."

Main metadata added:

- `structural_section_heading`
- `structural_section_path`
- `structural_section_level`
- `structural_chunk_kind`

Structured evidence representation added under `structured_content.structure`:

- `section_heading`
- `section_path`
- `section_level`
- `chunk_kind`

Primary files touched:

- `apps/api/src/hallu_defense/services/retrieval.py`
- `apps/api/src/hallu_defense/services/rag_index.py`
- `apps/api/tests/test_rag_index_adapters.py`

### RAG: Persistence And Structure Reconstruction

Persistent index adapters were updated so OpenSearch or other persistent
backends can reconstruct section structure from flattened metadata.

Tests were added for:

- Markdown section indexing.
- Structural metadata.
- Inline retrieval structure.
- Reconstruction from persistent/OpenSearch-style backend output.

### Evals: Persistent Scenario History

`evals/runners/scenarios.py` was extended to write/update:

```text
evals/reports/scenario-history.json
```

Each history entry includes:

- `run_id`
- `created_at`
- `metrics`

The history is capped at the last 50 runs to avoid unbounded growth. Corrupt or
unexpected history structure is supposed to fail explicitly instead of being
accepted silently.

Primary files:

- `evals/runners/scenarios.py`
- `apps/api/tests/test_eval_scenarios.py`
- `evals/reports/scenario-history.json`
- `evals/reports/scenario-metrics.json`

### Public Contracts For Eval History

Versioned public contracts were added for scenario history:

- JSON Schemas.
- TypeScript interfaces.
- Valid examples.
- Invalid examples.
- Contract validator coverage.

Primary files:

- `packages/contracts/src/index.ts`
- `packages/contracts/schemas/eval-scenario-history-entry.schema.json`
- `packages/contracts/schemas/eval-scenario-history-report.schema.json`
- `packages/contracts/examples/valid/eval-scenario-history-entry.json`
- `packages/contracts/examples/valid/eval-scenario-history-report.json`
- `packages/contracts/examples/invalid/eval-scenario-history-entry.json`
- `packages/contracts/examples/invalid/eval-scenario-history-report.json`
- `docs/schemas/README.md`

### Next.js Console Eval Trends

The console was updated to load scenario history and show trends:

- Latest pass rate.
- Delta against previous run.
- Latest p95 latency.
- Delta of p95 latency.
- Recent runs list.
- Date/run id.
- Main counts.

Primary files:

- `apps/console/lib/eval-report.ts`
- `apps/console/lib/eval-report.test.ts`
- `apps/console/app/page.tsx`
- `apps/console/app/run-console.tsx`
- `apps/console/app/globals.css`

Parser validation was added to reject malformed payloads and duplicate
`run_id` values.

## Documentation Updated In That Session

- `docs/TRACEABILITY_MATRIX.md`
- `docs/WORKLOG.md`

Requirements advanced included:

- `RAG-002`
- `EVAL-002`
- `TS-009`
- `CTR-022`
- `CI-003`
- `CI-004`
- `CI-006`

The platform was not marked globally complete or accepted.

## Validation Evidence From That Session

- `.venv\Scripts\python -m pytest apps\api\tests -q`: `267 passed`.
- `.venv\Scripts\python -m ruff check apps\api\src apps\api\tests scripts evals`:
  passed.
- `.venv\Scripts\python -m mypy apps\api\src`: success, no issues in 37
  source files.
- `.venv\Scripts\python evals\runners\scenarios.py`: 21 scenarios,
  `pass_rate=1.0`.
- `.venv\Scripts\python scripts\ci\check_json_schemas.py`: 55 schemas, 55
  valid examples, 55 invalid examples, 55 TypeScript interfaces validated.
- `npm run typecheck`: passed.
- `npm run test`: passed.
- `npm run build`: passed.
- `npm audit --omit dev`: 0 vulnerabilities.
- `.venv\Scripts\python scripts\ci\secret_scan.py`: no obvious secrets found.
- `git diff --check`: no errors.
- Local console HTTP check returned 200 and rendered eval scenario content.

## Risks And Blockers Reported Then

Historical blockers from that session:

- Git had no valid `HEAD`, blocking normal branches/worktrees/PR flow.
- Fable did not produce an integrable diff.
- `.claude-fable-work/scenario-history` existed only as auxiliary evidence and
  must not be treated as authoritative.

Current status:

- The Git `HEAD` blocker is fixed.
- Fable can now be launched through saved Claude Code workflow.
- Legacy auxiliary copies remain ignored and non-authoritative.

Remaining product risks still relevant:

- Full enterprise runtime implementation is incomplete.
- More durable multi-tenant persistence work remains.
- Console workflows are not complete for every operational surface.
- Human approval workflows and sandbox integration need further hardening.
- Observability and OIDC/RBAC need deployment-level validation.
- Eval history exists, but live ingestion/calibration remains future work.

## Recommended Next Step From That Report

The report recommended resolving Git state first, then continuing with
persistent retrieval isolation by tenant and explicit no-cross-tenant retrieval
tests.

Git state has now been repaired. The retrieval-persistence recommendation
remains a valid candidate for a future bounded Fable slice, but Codex should
select the next slice from the current traceability matrix and repository state.
