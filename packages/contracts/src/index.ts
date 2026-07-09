export type ClaimType =
  | "world_fact"
  | "doc_grounded"
  | "tool_observation"
  | "repo_state"
  | "test_result"
  | "computed_value"
  | "policy_claim"
  | "proposed_action"
  | "creative_statement"
  | "opinion";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type EvidenceKind =
  | "document_chunk"
  | "web_source"
  | "tool_output"
  | "repo_file"
  | "command_output"
  | "policy_rule"
  | "calculation";

export type Authority = "official" | "internal" | "trusted_third_party" | "unknown";

export type StalenessClass = "fresh" | "acceptable" | "stale" | "unknown";

export type VerdictStatus =
  | "SUPPORTED"
  | "PARTIALLY_SUPPORTED"
  | "CONTRADICTED"
  | "NOT_FOUND"
  | "AMBIGUOUS"
  | "STALE_SOURCE"
  | "UNVERIFIABLE"
  | "OUT_OF_SCOPE";

export type VerdictAction =
  | "allow"
  | "allow_with_citation"
  | "rewrite"
  | "abstain"
  | "ask_clarification"
  | "block"
  | "require_human_review";

export type FinalDecision =
  | "allow"
  | "repaired"
  | "abstained"
  | "blocked"
  | "require_human_review";

export type ApprovalStatus = "pending" | "approved" | "rejected";

export type ApprovalDecision = "approve" | "reject";

export interface SourceSpan {
  readonly message_id: string;
  readonly start_char: number;
  readonly end_char: number;
}

export interface Freshness {
  readonly retrieved_at: string;
  readonly published_at?: string | null;
  readonly staleness_class: StalenessClass;
}

export interface Claim {
  readonly claim_id: string;
  readonly text: string;
  readonly canonical_form: string;
  readonly type: ClaimType;
  readonly risk_level: RiskLevel;
  readonly requires_evidence: boolean;
  readonly source_span?: SourceSpan | null;
  readonly metadata: Readonly<Record<string, unknown>>;
}

export interface Evidence {
  readonly evidence_id: string;
  readonly kind: EvidenceKind;
  readonly source_ref: string;
  readonly content: string;
  readonly structured_content: Readonly<Record<string, unknown>>;
  readonly authority: Authority;
  readonly freshness: Freshness;
}

export interface ClaimVerdict {
  readonly claim_id: string;
  readonly status: VerdictStatus;
  readonly confidence: number;
  readonly evidence_ids: readonly string[];
  readonly action: VerdictAction;
  readonly reason: string;
  readonly validator_trace: Readonly<Record<string, unknown>>;
}

export interface ErrorResponse {
  readonly trace_id: string;
  readonly error: string;
  readonly message: string;
  readonly details: Readonly<Record<string, unknown>>;
}

export interface AuditEvent {
  readonly event_id: string;
  readonly trace_id: string;
  readonly tenant_id: string;
  readonly event_type: string;
  readonly method: string;
  readonly path: string;
  readonly status_code: number;
  readonly outcome: string;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly created_at: string;
}

export interface DocumentInput {
  readonly source_ref: string;
  readonly content: string;
  readonly authority: Authority;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ClaimExtractionRequest {
  readonly message_text: string;
  readonly conversation_slice?: readonly string[];
  readonly tool_outputs?: readonly Evidence[];
  readonly execution_artifacts?: Readonly<Record<string, unknown>>;
  readonly task_type?: string;
  readonly message_id?: string;
}

export interface ClaimExtractionResponse {
  readonly claims: readonly Claim[];
}

export interface ClaimClassificationRequest {
  readonly claims: readonly Claim[];
  readonly task_type?: string;
}

export interface ClaimClassificationResponse {
  readonly claims: readonly Claim[];
}

export interface EvidenceRetrievalRequest {
  readonly claims: readonly Claim[];
  readonly documents?: readonly DocumentInput[];
  readonly context_refs?: readonly string[];
  readonly metadata_filter?: Readonly<Record<string, unknown>>;
  readonly max_evidence_per_claim?: number;
}

export interface DocumentIngestionRequest {
  readonly documents: readonly DocumentInput[];
  readonly corpus_id?: string;
}

export interface DocumentIngestionResponse {
  readonly trace_id: string;
  readonly tenant_id: string;
  readonly corpus_id: string;
  readonly backend: string;
  readonly document_count: number;
  readonly indexed_count: number;
  readonly evidence_ids: readonly string[];
  readonly warnings: readonly string[];
}

export interface CorpusGrant {
  readonly tenant_id: string;
  readonly corpus_id: string;
  readonly reader_roles: readonly string[];
  readonly writer_roles: readonly string[];
  readonly version: number;
  readonly created_by: string;
  readonly updated_by: string;
  readonly created_at: string;
  readonly updated_at: string;
  readonly disabled_by?: string | null;
  readonly disabled_at?: string | null;
}

export interface CorpusGrantUpsertRequest {
  readonly corpus_id: string;
  readonly reader_roles?: readonly string[];
  readonly writer_roles?: readonly string[];
  readonly expected_version?: number | null;
}

export interface CorpusGrantListRequest {
  readonly corpus_id?: string | null;
  readonly include_disabled?: boolean;
  readonly limit?: number;
  readonly cursor?: string | null;
}

export interface CorpusGrantHistoryRequest {
  readonly corpus_id?: string | null;
  readonly actor_id?: string | null;
  readonly updated_at_from?: string | null;
  readonly updated_at_to?: string | null;
  readonly limit?: number;
  readonly cursor?: string | null;
}

export interface CorpusGrantHistoryDiffRequest extends CorpusGrantHistoryRequest {}

export interface CorpusGrantHistoryDiff {
  readonly tenant_id: string;
  readonly corpus_id: string;
  readonly version: number;
  readonly previous_version?: number | null;
  readonly action: "create" | "update" | "disable" | "reenable";
  readonly changed_fields: readonly ("reader_roles" | "writer_roles" | "disabled_state")[];
  readonly reader_roles_added: readonly string[];
  readonly reader_roles_removed: readonly string[];
  readonly writer_roles_added: readonly string[];
  readonly writer_roles_removed: readonly string[];
  readonly updated_by: string;
  readonly updated_at: string;
}

export interface CorpusGrantDisableRequest {
  readonly corpus_id: string;
  readonly expected_version?: number | null;
}

export interface CorpusGrantResponse {
  readonly grant: CorpusGrant;
}

export interface CorpusGrantListResponse {
  readonly grants: readonly CorpusGrant[];
  readonly next_cursor?: string | null;
}

export interface CorpusGrantHistoryResponse {
  readonly grants: readonly CorpusGrant[];
  readonly next_cursor?: string | null;
}

export interface CorpusGrantHistoryDiffResponse {
  readonly diffs: readonly CorpusGrantHistoryDiff[];
  readonly next_cursor?: string | null;
}

export interface VerificationRunRequest {
  readonly tenant_id?: string;
  readonly message_text: string;
  readonly documents?: readonly DocumentInput[];
  readonly tool_outputs?: readonly Evidence[];
  readonly execution_artifacts?: Readonly<Record<string, unknown>>;
  readonly task_type?: string;
  readonly message_id?: string;
}

export interface VerificationRun {
  readonly trace_id: string;
  readonly tenant_id: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly claims: readonly Claim[];
  readonly evidence: readonly Evidence[];
  readonly verdicts: readonly ClaimVerdict[];
  readonly final_decision: FinalDecision;
  readonly final_text: string;
  readonly policy_version: string;
  readonly created_at: string;
}

export interface VerificationReplayRequest {
  readonly trace_id: string;
}

export interface VerificationReplayResponse {
  readonly trace_id: string;
  readonly source_trace_id: string;
  readonly source_created_at: string;
  readonly source_final_decision: FinalDecision;
  readonly decision_changed: boolean;
  readonly replayed_run: VerificationRun;
}

export interface ToolCallEnvelope {
  readonly tool_name: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly schema: Readonly<Record<string, unknown>>;
  readonly risk_level: RiskLevel;
  readonly approval_required: boolean;
  readonly caller_context: Readonly<Record<string, unknown>>;
  readonly approval_id?: string | null;
  readonly approval_execution_token?: string | null;
}

export interface ToolValidationResponse {
  readonly allowed: boolean;
  readonly action: VerdictAction;
  readonly reason: string;
  readonly approval_required: boolean;
  readonly approval_id?: string | null;
  readonly sanitized_output?: Readonly<Record<string, unknown>> | null;
}

export interface ApprovalRecord {
  readonly approval_id: string;
  readonly tenant_id: string;
  readonly trace_id: string;
  readonly tool_call: ToolCallEnvelope;
  readonly status: ApprovalStatus;
  readonly risk_level: RiskLevel;
  readonly reason: string;
  readonly requested_by: string;
  readonly decided_by?: string | null;
  readonly decision_reason?: string | null;
  readonly created_at: string;
  readonly decided_at?: string | null;
}

export interface ApprovalExecutionGrant {
  readonly approval_id: string;
  readonly tenant_id: string;
  readonly tool_name: string;
  readonly execution_token: string;
  readonly expires_at: string;
}

export interface ApprovalListRequest {
  readonly status?: ApprovalStatus | null;
  readonly trace_id?: string | null;
}

export interface ApprovalListResponse {
  readonly approvals: readonly ApprovalRecord[];
}

export interface ApprovalDecisionRequest {
  readonly approval_id: string;
  readonly decision: ApprovalDecision;
  readonly decided_by?: string | null;
  readonly reason?: string;
}

export interface ApprovalDecisionResponse {
  readonly approval: ApprovalRecord;
  readonly execution_grant: ApprovalExecutionGrant | null;
}

export interface ResponseRepairRequest {
  readonly original_text: string;
  readonly claims: readonly Claim[];
  readonly verdicts: readonly ClaimVerdict[];
  readonly evidence?: readonly Evidence[];
}

export interface ResponseRepairResponse {
  readonly final_text: string;
  readonly final_decision: FinalDecision;
  readonly blocked_claim_ids: readonly string[];
  readonly repaired_claim_ids: readonly string[];
}

export interface PolicyEvaluationRequest {
  readonly subject?: string;
  readonly action: string;
  readonly resource?: string;
  readonly risk_level?: RiskLevel;
  readonly attributes?: Readonly<Record<string, unknown>>;
}

export interface PolicyEvaluationResponse {
  readonly trace_id: string;
  readonly allowed: boolean;
  readonly action: VerdictAction;
  readonly policy_version: string;
  readonly matched_rules: readonly string[];
  readonly explanation: string;
}

export interface RepoChecksRunRequest {
  readonly repo_ref?: string;
  readonly commands: readonly string[];
  readonly network_policy?: "deny" | "allowlisted";
}

export interface SandboxRun {
  readonly repo_ref: string;
  readonly commands: readonly string[];
  readonly exit_codes: readonly number[];
  readonly stdout: readonly string[];
  readonly stderr: readonly string[];
  readonly artifacts: readonly string[];
  readonly evidence: readonly Evidence[];
  readonly network_policy: "deny" | "allowlisted";
  readonly verdict: VerdictStatus;
}

export interface AuditExportRequest {
  readonly tenant_id?: string | null;
  readonly trace_id?: string | null;
  readonly include_events?: boolean;
}

export interface AuditExportResponse {
  readonly trace_id: string;
  readonly runs: readonly VerificationRun[];
  readonly events: readonly AuditEvent[];
}

export interface EvidenceRetrievalResponse {
  readonly evidence: readonly Evidence[];
  readonly claim_evidence_map: Readonly<Record<string, readonly string[]>>;
}

export interface ClaimVerificationRequest {
  readonly claims: readonly Claim[];
  readonly evidence?: readonly Evidence[];
}

export interface ClaimVerificationResponse {
  readonly verdicts: readonly ClaimVerdict[];
}

export interface EvalSmokeMetrics {
  readonly scenario_count: number;
  readonly final_decision_accuracy: number;
  readonly trace_coverage: number;
  readonly claim_ledger_coverage: number;
  readonly verdict_ledger_coverage: number;
  readonly claim_precision: number;
  readonly claim_recall: number;
  readonly unsupported_claim_recall: number;
  readonly groundedness: number;
  readonly faithfulness: number;
  readonly false_positive_blocking: number;
  readonly critical_pass_through: number;
  readonly p95_latency_ms: number;
  readonly cost_per_run_usd: number;
}

export interface EvalSmokeScenarioResult {
  readonly id: string;
  readonly latency_ms: number;
  readonly expected_final_decision: FinalDecision;
  readonly final_decision: FinalDecision;
  readonly trace_present: boolean;
  readonly claim_ledger_present: boolean;
  readonly verdict_ledger_present: boolean;
  readonly expected_claims: readonly string[];
  readonly actual_claims: readonly string[];
  readonly expected_unsupported_claims: readonly string[];
  readonly unsupported_hits: number;
  readonly supported_verdicts: number;
  readonly supported_verdicts_with_evidence: number;
  readonly verdict_count: number;
  readonly cost_usd: number;
}

export interface EvalSmokeReport {
  readonly metrics: EvalSmokeMetrics;
  readonly scenarios: readonly EvalSmokeScenarioResult[];
}

export interface EvalScenarioMetrics {
  readonly scenario_count: number;
  readonly passed_count: number;
  readonly pass_rate: number;
  readonly category_pass_rate: Readonly<Record<string, number>>;
  readonly verification_decision_accuracy: number;
  readonly blocked_high_risk_rate: number;
  readonly secret_redaction_rate: number;
  readonly prompt_injection_block_rate: number;
  readonly data_poisoning_block_rate: number;
  readonly tool_contradiction_guard_rate: number;
  readonly repo_false_claim_block_rate: number;
  readonly repo_semantic_claim_decision_accuracy: number;
  readonly sandbox_block_rate: number;
  readonly p95_latency_ms: number;
}

export interface EvalScenarioResult {
  readonly id: string;
  readonly kind: string;
  readonly category: string;
  readonly latency_ms: number;
  readonly expected: Readonly<Record<string, unknown>>;
  readonly observed: Readonly<Record<string, unknown>>;
  readonly passed: boolean;
  readonly failures: readonly string[];
}

export interface EvalScenarioReport {
  readonly metrics: EvalScenarioMetrics;
  readonly scenarios: readonly EvalScenarioResult[];
}

export interface EvalScenarioHistoryEntry {
  readonly run_id: string;
  readonly created_at: string;
  readonly metrics: EvalScenarioMetrics;
}

export interface EvalScenarioHistoryReport {
  readonly runs: readonly EvalScenarioHistoryEntry[];
}
