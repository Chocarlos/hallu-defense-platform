# Fable Delegation Runbook

Status: operational as of 2026-07-08.

## Purpose

Use Claude Fable 5 as a scoped teammate for large slices while Codex remains
responsible for integration, validation, traceability, and final reporting.

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
    task: "Implement the exact delegated slice here.",
    validation: "Run the focused commands that prove this slice.",
  },
})
```

Use `mode: "read"` for audits, surveys, or second opinions that must not edit
files.

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

1. Delegate only bounded work with a clear write scope.
2. Let Fable work in an isolated worktree.
3. Inspect the actual diff before trusting the summary.
4. Run focused validation from the main workspace after integrating.
5. Update `docs/TRACEABILITY_MATRIX.md` and `docs/WORKLOG.md`.
6. Report evidence, risks, and the next recommended slice.

## Verified Evidence

- `git rev-parse --verify HEAD` resolves to
  `8dec1b3b4c63ba65fad7a9664da68e88bbbc644a`.
- Fable workflow probe returned `model: "claude-fable-5"`,
  `headResolves: true`, `shortHead: "8dec1b3"`, and
  `agentsMdVisible: true`.
- Dedicated worktree `fable5/delegation` exists at commit `8dec1b3`.
