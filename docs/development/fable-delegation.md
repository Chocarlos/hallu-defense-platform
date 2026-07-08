# Fable Delegation Runbook

Status: operational as of 2026-07-08.

## Purpose

Use Claude Fable 5 as a scoped teammate for large slices while Codex remains
responsible for integration, validation, traceability, and final reporting.
Before any implementation delegation, Fable must receive the canonical project
context in `docs/development/fable-project-brief.md`.

## Current Route

The direct `mcp__claude_code.Agent` route does not expose registered local agent
types in this session. The supported route is the Claude Code `Workflow` tool
with `model: "fable"` and git worktree isolation.

On 2026-07-08, Codex retried the direct route with `model: "fable"`,
`mode: "auto"`, and worktree isolation so Fable could run with automatic
permissions. The route still failed with `Agent type 'general-purpose' not
found`. Use workflow-based Fable batches until that direct route exposes a
usable agent type in this session.

Reusable workflow:

```text
.claude/workflows/fable-delegate.js
```

Call it with:

```js
Workflow({
  scriptPath: ".claude/workflows/fable-delegate.js",
  args: {
    mode: "write",
    goal: "Explain the product-level goal this task advances.",
    context: "Add any current-session context, constraints, or prior findings.",
    task: "Implement the exact delegated slice here.",
    acceptance: "State exactly what must be true for this delegated slice to count as done.",
    validation: "Run the focused commands that prove this slice.",
  },
})
```

Use `mode: "read"` for audits, surveys, or second opinions that must not edit
files.

For broad product work, delegate batches rather than one-off large tasks. The
current batch backlog is recorded in
`docs/development/fable-enterprise-batch.md`.

Write mode intentionally fails unless `goal` and `acceptance` are supplied.
This prevents sending Fable implementation work without context, target outcome,
and a clear done condition.

## Required Context

Fable must read these before implementation:

- `AGENTS.md`
- `docs/PLAN_MASTER.md`
- `docs/TRACEABILITY_MATRIX.md`
- `docs/WORKLOG.md`
- `docs/development/fable-project-brief.md`
- `docs/development/fable-prior-session-report.md`

The project brief summarizes the mission, current state, previous Codex work,
environment constraints, expected end state, near-term direction, and the
division of responsibility between Fable and Codex.
The prior-session report preserves the user-supplied historical report,
including what was built, what was validated, and which Fable/Git blockers were
later resolved.

## Isolation

- Main repository branch: `master`.
- Baseline commit that fixed missing `HEAD`: `8dec1b3`.
- Pre-refresh verified delegation context commit: `4ac9df5`.
- Persistent Fable branch: `fable5/delegation`.
- Persistent Fable worktree:
  `.claude/worktrees/fable5-delegation`.
- Keep `master` and `fable5/delegation` aligned before launching write-mode
  implementation work.
- Temporary workflow worktrees are created under `.claude/worktrees/` and are
  ignored by Git.
- Legacy auxiliary copies `.codex-fable-work/` and `.claude-fable-work/` are
  ignored and must not be integrated without explicit inspection.

## Integration Protocol

1. Run read-only orientation or audit first when the scope is broad.
2. Delegate only bounded work with a clear write scope.
3. Provide `goal`, `context`, `task`, `acceptance`, and `validation`.
4. Let Fable work in an isolated worktree.
5. Inspect the actual diff before trusting the summary.
6. Run focused validation from the main workspace after integrating.
7. Update `docs/TRACEABILITY_MATRIX.md` and `docs/WORKLOG.md`.
8. Report evidence, risks, and the next recommended slice.

## Verified Evidence

- `git rev-parse --verify HEAD` resolves to
  `4ac9df52d37c5999c6aaae7c567c124e51b9a026`.
- `git rev-parse --verify fable5/delegation` resolves to the same commit.
- Fable workflow probe returned `model: "claude-fable-5"`,
  `headResolves: true`, `shortHead: "8dec1b3"`, and
  `agentsMdVisible: true`.
- Saved context-package workflow probe `wf_e4e6e96f-aa3` returned
  `success=true`, `projectBriefRead=true`, `priorSessionReportRead=true`,
  `acceptanceMet=true`, and no changed files.
- Dedicated worktree `fable5/delegation` existed at commit `4ac9df5` before
  the coordination refresh and must be fast-forwarded with `master` before
  follow-up write-mode delegations.
