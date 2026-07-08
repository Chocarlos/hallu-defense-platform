# Fable Enterprise Batch Backlog

Status: active delegation plan as of 2026-07-08.

Codex keeps lighter, locally verifiable slices on `master`. Fable owns the
larger product blocks, in batch, with disjoint scopes and Codex audit before
integration.

## Active Batch

- Workflow: `wf_6e5f935f-e44`.
- Base commit: `1aad178`.
- Branches aligned before launch: `master` and `fable5/delegation`.
- Direct auto-permission route attempted first with `mcp__claude_code.Agent`,
  `model=fable`, `mode=auto`, and worktree isolation.
- Direct route failed with `Agent type 'general-purpose' not found`.
- Fallback route: Claude Code `Workflow` with five parallel Fable agents using
  worktree isolation.

## Fable Blocks

1. RAG live persistence and tenant isolation.
   - Persistent OpenSearch/pgvector retrieval boundaries.
   - No-cross-tenant reads.
   - Same public evidence IDs across tenants without overwrite/cross-read.
   - Corpus grant enforcement and structural metadata reconstruction.

2. Semantic verification and provider-backed NLI hardening.
   - Fail-closed provider adjudication.
   - Safe prompts and validator traces.
   - Evidence ID allowlisting.
   - No provider NLI for repo/test/build deterministic claims.

3. Console enterprise workflows.
   - Replay UI for prior `VerificationRun` by `trace_id`.
   - Approval queue interaction coverage.
   - Audit/policy/approval operational views without demo fallback.

4. Production runtime validation gates.
   - Docker/OpenSearch/Postgres/MinIO/Redis/Grafana/OTel/OIDC/Vault/backup
     runtime uncertainty reduced through executable config or dry-run gates.
   - No claim of live service validation unless the service actually runs.

5. Contract/codegen drift reduction.
   - Reduce manual synchronization risk across TypeScript, JSON Schema,
     Pydantic, examples, and OpenAPI.
   - Prefer deterministic drift checks over broad risky code generation.

## Integration Rule

Fable output is not authoritative until Codex:

1. Inspects actual diffs.
2. Rejects blocked/no-diff summaries.
3. Runs focused validation from `master`.
4. Updates traceability and worklog.
5. Commits accepted changes.
6. Fast-forwards `fable5/delegation` back to `master`.
