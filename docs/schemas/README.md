# Schema Artifacts

Canonical JSON Schemas currently live in `packages/contracts/schemas`.

The current schema set covers the core public contracts plus the request/response contracts used by the SDK and MCP tool boundary:

- `SourceSpan`
- `Freshness`
- `Claim`
- `ClaimExtractionRequest`
- `ClaimExtractionResponse`
- `ClaimClassificationRequest`
- `ClaimClassificationResponse`
- `ClaimVerificationRequest`
- `ClaimVerificationResponse`
- `Evidence`
- `DocumentIngestionRequest`
- `DocumentIngestionResponse`
- `DocumentIngestionStatusRequest`
- `DocumentIngestionStatusResponse`
- `EvidenceRetrievalRequest`
- `EvidenceRetrievalResponse`
- `ClaimVerdict`
- `VerificationRun`
- `VerificationRunRequest`
- `DocumentInput`
- `ToolCallEnvelope`
- `ToolValidationResponse`
- `CorpusGrant`
- `CorpusGrantUpsertRequest`
- `CorpusGrantDisableRequest`
- `CorpusGrantListRequest`
- `CorpusGrantHistoryRequest`
- `CorpusGrantHistoryDiff`
- `CorpusGrantHistoryDiffRequest`
- `CorpusGrantResponse`
- `CorpusGrantListResponse`
- `CorpusGrantHistoryResponse`
- `CorpusGrantHistoryDiffResponse`
- `ResponseRepairRequest`
- `ResponseRepairResponse`
- `PolicyEvaluationRequest`
- `PolicyEvaluationResponse`
- `RepoChecksRunRequest`
- `SandboxRun`
- `ErrorResponse`
- `AuditEvent`
- `AuditExportRequest`
- `AuditExportResponse`
- `EvalSmokeMetrics`
- `EvalSmokeScenarioResult`
- `EvalSmokeReport`
- `EvalScenarioMetrics`
- `EvalScenarioResult`
- `EvalScenarioReport`
- `EvalScenarioHistoryEntry`
- `EvalScenarioHistoryReport`
- `ApprovalRecord`
- `ApprovalListRequest`
- `ApprovalListResponse`
- `ApprovalDecisionRequest`
- `ApprovalDecisionResponse`
- `ApprovalExecutionGrant`

Future work should either generate this directory from the canonical schemas or move canonical schemas here and generate language bindings from them.

Valid and invalid contract examples live in `packages/contracts/examples`.

`EvidenceRetrievalRequest` includes optional `metadata_filter` support for exact-match local retrieval filters.
`ToolValidationResponse` can include an `approval_id` when a high-risk tool call is queued for human review.
`DocumentIngestionResponse` can include `job_id` and `job_status` when async ingestion mode queues work; `DocumentIngestionStatusRequest` and `DocumentIngestionStatusResponse` cover tenant-scoped status lookup for those jobs.
`ApprovalDecisionResponse` includes an `ApprovalExecutionGrant` when a high-risk tool call is approved; executors must present the grant on a later input validation call before running the tool.
`ApprovalDecisionRequest.decided_by` is optional and deprecated for API callers; `/approvals/decide` persists reviewer identity from the authenticated request principal.
`CorpusGrant` records tenant-scoped reader and writer roles, lifecycle `version`, and optional disabled state for a RAG corpus; `/rag/corpus-grants/upsert` and `/rag/corpus-grants/disable` require a `rag_writer` principal, accept optional `expected_version` optimistic concurrency tokens, return `409` on stale versions, while `/rag/corpus-grants/list`, `/rag/corpus-grants/history`, and `/rag/corpus-grants/history/diff` are readable by `rag_writer` or `verifier` and support cursor pagination. The list endpoint exposes latest state with disabled-grant filtering; the history endpoint exposes append-only revisions in tenant scope; the history diff endpoint exposes per-revision `action`, `previous_version`, changed role sets, and disabled-state changes. Both history endpoints can filter by `actor_id`, `updated_at_from`, and `updated_at_to`.
`SandboxRun` includes typed `evidence` entries for command output and sandbox inspection artifacts so repo-check results can feed claim verification directly.
`EvalSmokeReport` mirrors the real `evals/reports/smoke-metrics.json` artifact emitted by the smoke eval runner so the console can render eval outcomes without mock data or a new backend.
`EvalScenarioReport` mirrors the real `evals/reports/scenario-metrics.json` artifact emitted by the expanded offline scenario runner, including category pass rates and code-agent/security guardrail metrics.
`EvalScenarioHistoryReport` mirrors the real `evals/reports/scenario-history.json` artifact emitted by the expanded offline scenario runner, preserving recent run metrics for console trend comparison.

The schema gate is:

```powershell
.\.venv\Scripts\python scripts/ci/check_json_schemas.py
```
