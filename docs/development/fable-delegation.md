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
- Persistent Fable branch: `fable5/delegation`.
- Persistent Fable worktree:
  `.claude/worktrees/fable5-delegation`.
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
  `8dec1b3b4c63ba65fad7a9664da68e88bbbc644a`.
- Fable workflow probe returned `model: "claude-fable-5"`,
  `headResolves: true`, `shortHead: "8dec1b3"`, and
  `agentsMdVisible: true`.
- Dedicated worktree `fable5/delegation` exists at commit `8dec1b3`.
