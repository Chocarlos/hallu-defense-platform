# ADR 0005: Sandbox Model

## Status

Accepted for foundation.

## Context

Code agents can hallucinate about files, functions, tests, builds, and diffs. Text-only verification is not enough.

## Decision

Sandbox defaults:

- Network denied.
- Filesystem scoped to configured workspace.
- Commands are allowlisted.
- stdout, stderr, exit codes, and artifacts are captured.
- Claims about repo/test/build success require `SandboxRun` or equivalent deterministic evidence.

## Consequences

- Sandbox checks may be slower than text validation but are required for correctness.
- Future work must add artifact capture, git diff inspection, AST/static checks, and stronger network enforcement.

