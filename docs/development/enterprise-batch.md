# Enterprise Batch Backlog

Status: historical batch plan from 2026-07-08; superseded by the current plan,
traceability matrix, worklog, and `enterprise-batch-2.md`.

The integration lead keeps lighter, locally verifiable slices on `master`. Secondary
leaders own larger product blocks in batches with disjoint scopes and root audit before
integration.

## Historical Workstreams

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

Contributor output is not authoritative until the integration owner:

1. Inspects actual diffs.
2. Rejects blocked/no-diff summaries.
3. Runs focused validation from `master`.
4. Updates traceability and worklog.
5. Commits accepted changes.
6. Integrates only the reviewed commit through the repository's protected
   branch workflow.
