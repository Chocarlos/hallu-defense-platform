from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ClaimType(StrEnum):
    WORLD_FACT = "world_fact"
    DOC_GROUNDED = "doc_grounded"
    TOOL_OBSERVATION = "tool_observation"
    REPO_STATE = "repo_state"
    TEST_RESULT = "test_result"
    COMPUTED_VALUE = "computed_value"
    POLICY_CLAIM = "policy_claim"
    PROPOSED_ACTION = "proposed_action"
    CREATIVE_STATEMENT = "creative_statement"
    OPINION = "opinion"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceKind(StrEnum):
    DOCUMENT_CHUNK = "document_chunk"
    WEB_SOURCE = "web_source"
    TOOL_OUTPUT = "tool_output"
    REPO_FILE = "repo_file"
    COMMAND_OUTPUT = "command_output"
    POLICY_RULE = "policy_rule"
    CALCULATION = "calculation"


class Authority(StrEnum):
    OFFICIAL = "official"
    INTERNAL = "internal"
    TRUSTED_THIRD_PARTY = "trusted_third_party"
    UNKNOWN = "unknown"


class StalenessClass(StrEnum):
    FRESH = "fresh"
    ACCEPTABLE = "acceptable"
    STALE = "stale"
    UNKNOWN = "unknown"


class VerdictStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    NOT_FOUND = "NOT_FOUND"
    AMBIGUOUS = "AMBIGUOUS"
    STALE_SOURCE = "STALE_SOURCE"
    UNVERIFIABLE = "UNVERIFIABLE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class VerdictAction(StrEnum):
    ALLOW = "allow"
    ALLOW_WITH_CITATION = "allow_with_citation"
    REWRITE = "rewrite"
    ABSTAIN = "abstain"
    ASK_CLARIFICATION = "ask_clarification"
    BLOCK = "block"
    REQUIRE_HUMAN_REVIEW = "require_human_review"


class FinalDecision(StrEnum):
    ALLOW = "allow"
    REPAIRED = "repaired"
    ABSTAINED = "abstained"
    BLOCKED = "blocked"
    REQUIRE_HUMAN_REVIEW = "require_human_review"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class DocumentIngestionJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD = "dead"


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    error: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    trace_id: str
    tenant_id: str
    event_type: str
    method: str
    path: str
    status_code: int = Field(ge=100, le=599)
    outcome: str
    metadata: dict[str, object] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SourceSpan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str
    start_char: int = Field(ge=0)
    end_char: int = Field(ge=0)

    @field_validator("end_char")
    @classmethod
    def end_must_not_be_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("end_char must be non-negative")
        return value


class Freshness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    published_at: datetime | None = None
    staleness_class: StalenessClass = StalenessClass.UNKNOWN


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    text: str = Field(min_length=1)
    canonical_form: str = ""
    type: ClaimType = ClaimType.WORLD_FACT
    risk_level: RiskLevel = RiskLevel.MEDIUM
    requires_evidence: bool = True
    source_span: SourceSpan | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    kind: EvidenceKind
    source_ref: str = ""
    content: str = Field(min_length=1)
    structured_content: dict[str, object] = Field(default_factory=dict)
    authority: Authority = Authority.UNKNOWN
    freshness: Freshness = Field(default_factory=Freshness)


class ClaimVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    status: VerdictStatus
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)
    action: VerdictAction
    reason: str
    validator_trace: dict[str, object] = Field(default_factory=dict)


class DocumentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ref: str
    content: str = Field(min_length=1)
    authority: Authority = Authority.INTERNAL
    metadata: dict[str, object] = Field(default_factory=dict)


class ClaimExtractionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_text: str = Field(min_length=1)
    conversation_slice: list[str] = Field(default_factory=list)
    tool_outputs: list[Evidence] = Field(default_factory=list)
    execution_artifacts: dict[str, object] = Field(default_factory=dict)
    task_type: str = "chat"
    message_id: str = "draft"


class ClaimExtractionResponse(BaseModel):
    claims: list[Claim]


class ClaimClassificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claims: list[Claim]
    task_type: str = "chat"


class ClaimClassificationResponse(BaseModel):
    claims: list[Claim]


class EvidenceRetrievalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claims: list[Claim]
    documents: list[DocumentInput] = Field(default_factory=list)
    context_refs: list[str] = Field(default_factory=list)
    metadata_filter: dict[str, object] = Field(default_factory=dict)
    max_evidence_per_claim: int = Field(default=3, ge=1, le=10)


class EvidenceRetrievalResponse(BaseModel):
    evidence: list[Evidence]
    claim_evidence_map: dict[str, list[str]]


class DocumentIngestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    documents: list[DocumentInput] = Field(min_length=1, max_length=100)
    corpus_id: str = Field(default="default", min_length=1)


class DocumentIngestionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    tenant_id: str
    corpus_id: str
    backend: str
    document_count: int = Field(ge=0)
    indexed_count: int = Field(ge=0)
    evidence_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    job_id: str | None = Field(default=None, min_length=1)
    job_status: DocumentIngestionJobStatus | None = None


class DocumentIngestionStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(min_length=1)


class DocumentIngestionStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    tenant_id: str
    job_id: str
    corpus_id: str | None = None
    job_type: Literal["ingest", "reindex_corpus"]
    job_status: DocumentIngestionJobStatus
    attempts: int = Field(ge=0)
    available_at: datetime
    created_at: datetime
    updated_at: datetime


class CorpusGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    corpus_id: str = Field(min_length=1)
    reader_roles: list[str] = Field(default_factory=list)
    writer_roles: list[str] = Field(default_factory=list)
    version: int = Field(default=1, ge=1)
    created_by: str = Field(min_length=1)
    updated_by: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    disabled_by: str | None = Field(default=None, min_length=1)
    disabled_at: datetime | None = None

    @field_validator("reader_roles", "writer_roles")
    @classmethod
    def roles_must_be_non_empty_strings(cls, value: list[str]) -> list[str]:
        normalized = [role.strip() for role in value]
        if any(not role for role in normalized):
            raise ValueError("roles must contain only non-empty strings")
        return sorted(set(normalized))

    @model_validator(mode="after")
    def disabled_fields_must_match(self) -> CorpusGrant:
        if (self.disabled_at is None) != (self.disabled_by is None):
            raise ValueError("disabled_at and disabled_by must be set together")
        return self


class CorpusGrantUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_id: str = Field(min_length=1)
    reader_roles: list[str] = Field(default_factory=list)
    writer_roles: list[str] = Field(default_factory=list)
    expected_version: int | None = Field(default=None, ge=0)

    @field_validator("reader_roles", "writer_roles")
    @classmethod
    def roles_must_be_non_empty_strings(cls, value: list[str]) -> list[str]:
        normalized = [role.strip() for role in value]
        if any(not role for role in normalized):
            raise ValueError("roles must contain only non-empty strings")
        return sorted(set(normalized))


class CorpusGrantListRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_id: str | None = Field(default=None, min_length=1)
    include_disabled: bool = False
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = Field(default=None, min_length=1)


class CorpusGrantDisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_id: str = Field(min_length=1)
    expected_version: int | None = Field(default=None, ge=0)


class CorpusGrantHistoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    corpus_id: str | None = Field(default=None, min_length=1)
    actor_id: str | None = Field(default=None, min_length=1)
    updated_at_from: datetime | None = None
    updated_at_to: datetime | None = None
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = Field(default=None, min_length=1)


CorpusGrantHistoryDiffAction = Literal["create", "update", "disable", "reenable"]
CorpusGrantHistoryDiffField = Literal["reader_roles", "writer_roles", "disabled_state"]


class CorpusGrantHistoryDiff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    corpus_id: str = Field(min_length=1)
    version: int = Field(ge=1)
    previous_version: int | None = Field(default=None, ge=1)
    action: CorpusGrantHistoryDiffAction
    changed_fields: list[CorpusGrantHistoryDiffField] = Field(default_factory=list)
    reader_roles_added: list[str] = Field(default_factory=list)
    reader_roles_removed: list[str] = Field(default_factory=list)
    writer_roles_added: list[str] = Field(default_factory=list)
    writer_roles_removed: list[str] = Field(default_factory=list)
    updated_by: str = Field(min_length=1)
    updated_at: datetime


class CorpusGrantHistoryDiffRequest(CorpusGrantHistoryRequest):
    pass


class CorpusGrantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant: CorpusGrant


class CorpusGrantListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grants: list[CorpusGrant]
    next_cursor: str | None = None


class CorpusGrantHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grants: list[CorpusGrant]
    next_cursor: str | None = None


class CorpusGrantHistoryDiffResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    diffs: list[CorpusGrantHistoryDiff]
    next_cursor: str | None = None


class ClaimVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claims: list[Claim]
    evidence: list[Evidence] = Field(default_factory=list)


class ClaimVerificationResponse(BaseModel):
    verdicts: list[ClaimVerdict]


class ResponseRepairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    original_text: str
    claims: list[Claim]
    verdicts: list[ClaimVerdict]
    evidence: list[Evidence] = Field(default_factory=list)


class ResponseRepairResponse(BaseModel):
    final_text: str
    final_decision: FinalDecision
    blocked_claim_ids: list[str] = Field(default_factory=list)
    repaired_claim_ids: list[str] = Field(default_factory=list)


class ToolCallEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    tool_name: str = Field(min_length=1)
    input: dict[str, object] = Field(default_factory=dict)
    tool_schema: dict[str, object] = Field(default_factory=dict, alias="schema")
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approval_required: bool = False
    caller_context: dict[str, object] = Field(default_factory=dict)
    approval_id: str | None = None
    approval_execution_token: str | None = None


class ToolValidationResponse(BaseModel):
    allowed: bool
    action: VerdictAction
    reason: str
    approval_required: bool = False
    approval_id: str | None = None
    sanitized_output: dict[str, object] | None = None


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    tenant_id: str
    trace_id: str
    tool_call: ToolCallEnvelope
    status: ApprovalStatus
    risk_level: RiskLevel
    reason: str
    requested_by: str = "system"
    decided_by: str | None = None
    decision_reason: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    decided_at: datetime | None = None


class ApprovalExecutionGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    execution_token: str = Field(min_length=16)
    expires_at: datetime


class ApprovalListRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ApprovalStatus | None = ApprovalStatus.PENDING
    trace_id: str | None = None


class ApprovalListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approvals: list[ApprovalRecord]


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1)
    decision: ApprovalDecision
    decided_by: str | None = Field(default=None, min_length=1)
    reason: str = ""


class ApprovalDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval: ApprovalRecord
    execution_grant: ApprovalExecutionGrant | None = None


class PolicyEvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = "anonymous"
    action: str
    resource: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    attributes: dict[str, object] = Field(default_factory=dict)


class PolicyEvaluationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    allowed: bool
    action: VerdictAction
    policy_version: str
    matched_rules: list[str]
    explanation: str


class RepoChecksRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_ref: str = "."
    commands: list[str] = Field(min_length=1, max_length=10)
    network_policy: Literal["deny", "allowlisted"] = "deny"


class SandboxRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_ref: str
    commands: list[str]
    exit_codes: list[int]
    stdout: list[str]
    stderr: list[str]
    artifacts: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    network_policy: Literal["deny", "allowlisted"] = "deny"
    verdict: VerdictStatus


class AuditExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str | None = None
    trace_id: str | None = None
    include_events: bool = True


class AuditExportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    runs: list["VerificationRun"]
    events: list[AuditEvent] = Field(default_factory=list)


class EvalReportMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_count: int = Field(ge=0)
    pass_rate: float = Field(ge=0, le=1)
    p95_latency_ms: float = Field(ge=0)
    groundedness: float | None = Field(default=None, ge=0, le=1)
    faithfulness: float | None = Field(default=None, ge=0, le=1)


class EvalReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(pattern=r"^evr_[A-Za-z0-9_-]+$")
    tenant_id: str = Field(min_length=1)
    suite: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    run_id: str = Field(min_length=1, max_length=120)
    source: str = Field(default="api", min_length=1, max_length=120)
    metrics: EvalReportMetrics
    payload: dict[str, object] = Field(default_factory=dict)
    published_by: str = Field(min_length=1)
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvalReportPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    run_id: str = Field(min_length=1, max_length=120)
    source: str = Field(default="api", min_length=1, max_length=120)
    metrics: EvalReportMetrics
    payload: dict[str, object] = Field(default_factory=dict)


class EvalReportPublishResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    report: EvalReport


class EvalReportListRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suite: str | None = Field(
        default=None,
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9_.-]+$",
    )
    limit: int = Field(default=50, ge=1, le=500)


class EvalReportListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    reports: list[EvalReport]


class VerificationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str | None = None
    message_text: str = Field(min_length=1)
    documents: list[DocumentInput] = Field(default_factory=list)
    tool_outputs: list[Evidence] = Field(default_factory=list)
    execution_artifacts: dict[str, object] = Field(default_factory=dict)
    task_type: str = "chat"
    message_id: str = "draft"


class VerificationRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    tenant_id: str
    input: dict[str, object]
    claims: list[Claim]
    evidence: list[Evidence]
    verdicts: list[ClaimVerdict]
    final_decision: FinalDecision
    final_text: str
    policy_version: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(min_length=1, pattern=r"^tr_[A-Za-z0-9_-]+$")


class VerificationReplayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(pattern=r"^tr_[A-Za-z0-9_-]+$")
    source_trace_id: str = Field(pattern=r"^tr_[A-Za-z0-9_-]+$")
    source_created_at: datetime
    source_final_decision: FinalDecision
    decision_changed: bool
    replayed_run: VerificationRun
