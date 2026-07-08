# ADR 0003: Verification Pipeline

## Status

Accepted for foundation.

## Context

Response-level pass/fail is too coarse. The system must reason claim-by-claim and action-by-action.

## Decision

Adopt this pipeline:

```text
input -> extract claims -> classify -> retrieve evidence -> verify
      -> detect contradictions -> decide action -> repair/abstain/block/allow
      -> VerificationRun -> audit ledger -> trace_id
```

## Consequences

- Every final answer must be explainable through claims, evidence, verdicts, policy version, validator trace, and audit events.
- Claims about tests, builds, files, functions, diffs, or repository state require deterministic evidence.

