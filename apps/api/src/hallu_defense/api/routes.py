from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response

from hallu_defense.config import Settings

from hallu_defense.api.dependencies import (
    RequestContext,
    approval_queue,
    audit_ledger,
    claim_classifier,
    claim_extractor,
    claim_verifier,
    corpus_grant_registry,
    document_ingestor,
    eval_report_repository,
    get_settings,
    get_readiness_service,
    hybrid_retriever,
    ingestion_job_queue,
    metrics_collector,
    orchestrator,
    policy_engine,
    rag_access_policy,
    require_endpoint_roles,
    require_metrics_access,
    response_repairer,
    sandbox_runner,
    telemetry,
    tool_safety,
    tool_validation_rate_limiter,
)
from hallu_defense.domain.models import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalListRequest,
    ApprovalListResponse,
    AuditExportRequest,
    AuditExportResponse,
    ClaimClassificationRequest,
    ClaimClassificationResponse,
    ClaimExtractionRequest,
    ClaimExtractionResponse,
    ClaimVerificationRequest,
    ClaimVerificationResponse,
    ClaimVerificationRequestV2,
    ClaimVerificationResponseV2,
    CorpusGrantDisableRequest,
    CorpusGrantHistoryDiffRequest,
    CorpusGrantHistoryDiffResponse,
    CorpusGrantHistoryRequest,
    CorpusGrantHistoryResponse,
    CorpusGrantListRequest,
    CorpusGrantListResponse,
    CorpusGrantResponse,
    CorpusGrantUpsertRequest,
    DocumentIngestionJobStatus,
    DocumentIngestionRequest,
    DocumentIngestionResponse,
    DocumentIngestionStatusRequest,
    DocumentIngestionStatusResponse,
    EvidenceRetrievalRequest,
    EvidenceRetrievalResponse,
    ErrorResponse,
    EvalReportListRequest,
    EvalReportListResponse,
    EvalReportPublishRequest,
    EvalReportPublishResponse,
    FinalDecision,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    RepoChecksRunRequest,
    ResponseRepairRequest,
    ResponseRepairResponse,
    SandboxRun,
    ToolCallEnvelope,
    ToolValidationResponse,
    VerificationReplayRequest,
    VerificationReplayResponse,
    VerificationRun,
    VerificationRunListRequest,
    VerificationRunListResponse,
    VerificationRunRequest,
    VerificationRunRequestV2,
    VerificationRunV2,
    V2_SCHEMA_VERSION,
    VerdictAction,
)
from hallu_defense.config import INGESTION_MODE_ASYNC
from hallu_defense.services.approvals import (
    ApprovalAlreadyDecidedError,
    ApprovalExecutionGrantError,
    ApprovalNotFoundError,
)
from hallu_defense.services.audit import AuditLedgerError, ReplaySourceConflictError
from hallu_defense.services.corpus_grants import (
    CorpusGrantNotFoundError,
    CorpusGrantPaginationError,
    CorpusGrantVersionConflictError,
)
from hallu_defense.services.contract_v2 import (
    convert_claim_verdict_v2,
    convert_verification_request_v1,
    convert_verification_run_v2,
)
from hallu_defense.services.ingestion_jobs import (
    IngestionJob,
    IngestionJobError,
    IngestionTenantDeletedError,
    IngestionJobType,
)
from hallu_defense.services.metrics import PROMETHEUS_CONTENT_TYPE
from hallu_defense.services.postgres import PostgresProviderError
from hallu_defense.services.rate_limit import RateLimitUnavailableError
from hallu_defense.services.rag_access import RagAccessDeniedError
from hallu_defense.services.rag_index import RagIndexError
from hallu_defense.services.readiness import ReadinessService
from hallu_defense.services.sandbox import SandboxError
from hallu_defense.services.verification_history import (
    VerificationHistoryCursorError,
    VerificationHistoryIntegrityError,
    list_verification_history,
)

LOGGER = logging.getLogger(__name__)
READINESS_UNAVAILABLE_MESSAGE = "Service dependencies are not ready."
RATE_LIMIT_UNAVAILABLE_MESSAGE = "Tool validation rate limit is unavailable."
AUDIT_HISTORY_UNAVAILABLE_MESSAGE = "Audit history is unavailable."
VERIFICATION_PERSISTENCE_UNAVAILABLE_MESSAGE = "Verification persistence is unavailable."
VERIFICATION_REPLAY_SOURCE_CONFLICT_MESSAGE = "Verification replay source is ambiguous."

ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse},
    401: {"model": ErrorResponse},
    403: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    408: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    413: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    500: {"model": ErrorResponse},
}

router = APIRouter(responses=ERROR_RESPONSES)


def _authenticated_tenant_id(
    requested_tenant_id: object | None,
    context: RequestContext,
) -> str:
    if requested_tenant_id is not None and requested_tenant_id != context.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Request tenant_id does not match the authenticated tenant.",
        )
    return context.tenant_id


def _record_verification_completed(
    run: VerificationRun,
    *,
    path: str,
    tenant_id: str,
    trace_id: str,
    source_trace_id: str | None = None,
    source_final_decision: FinalDecision | None = None,
) -> VerificationRun:
    if run.tenant_id != tenant_id or run.trace_id != trace_id:
        LOGGER.error(
            "verification completion identity mismatch",
            extra={"path": path},
        )
        raise HTTPException(
            status_code=503,
            detail=VERIFICATION_PERSISTENCE_UNAVAILABLE_MESSAGE,
        )
    try:
        if path == "/verification/replay":
            if source_trace_id is None or source_final_decision is None:
                raise AuditLedgerError("Replay completion metadata is incomplete.")
            completed = audit_ledger.append_replayed_run(
                run,
                source_trace_id=source_trace_id,
                source_final_decision=source_final_decision,
            )
        else:
            completed = audit_ledger.append_completed_run(run, path=path)
    except (AuditLedgerError, PostgresProviderError) as exc:
        LOGGER.error(
            "verification completion persistence failed",
            extra={"path": path, "exception_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=503,
            detail=VERIFICATION_PERSISTENCE_UNAVAILABLE_MESSAGE,
        ) from exc
    # The ledger stores a redacted snapshot. Preserve the public response
    # contract while adopting the canonical timestamp on an idempotent retry.
    return run.model_copy(update={"created_at": completed.run.created_at})


def _canonical_tool_call(
    request: ToolCallEnvelope,
    context: RequestContext,
) -> ToolCallEnvelope:
    caller_context = dict(request.caller_context)
    caller_context["tenant_id"] = _authenticated_tenant_id(
        caller_context.get("tenant_id"),
        context,
    )
    if context.principal.is_authenticated:
        caller_context["subject"] = context.principal.subject_id
    elif (
        not isinstance(caller_context.get("subject"), str)
        or not str(caller_context["subject"]).strip()
    ):
        caller_context["subject"] = "anonymous"
    return request.model_copy(update={"caller_context": caller_context}, deep=True)


def _enforce_tool_validation_rate_limit(
    *,
    context: RequestContext,
    tool_name: str,
    phase: str,
) -> ToolValidationResponse | None:
    try:
        allowed = tool_validation_rate_limiter.allow(
            tenant_id=context.tenant_id,
            subject_id=context.principal.subject_id,
            tool_name=f"{tool_name}:{phase}",
        )
    except RateLimitUnavailableError as exc:
        metrics_collector.record_tool_validation_rate_limit(outcome="unavailable")
        LOGGER.warning(
            "Tool-validation rate limit backend is unavailable.",
            extra={"exception_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=503,
            detail=RATE_LIMIT_UNAVAILABLE_MESSAGE,
        ) from exc
    if allowed:
        metrics_collector.record_tool_validation_rate_limit(outcome="allowed")
        return None
    metrics_collector.record_tool_validation_rate_limit(outcome="blocked")
    return ToolValidationResponse(
        allowed=False,
        action=VerdictAction.BLOCK,
        reason="Tool validation rate limit exceeded.",
        approval_required=False,
        trace_id=context.trace_id,
    )


@router.get("/health")
def health() -> dict[str, str]:
    settings = get_settings()
    return {"status": "ok", "environment": settings.environment}


@router.get(
    "/ready",
    response_model=dict[str, str],
    responses={503: {"model": ErrorResponse}},
)
def ready(
    readiness: ReadinessService = Depends(get_readiness_service),
) -> dict[str, str]:
    try:
        result = readiness.check()
    except Exception as exc:
        LOGGER.warning(
            "Readiness service failed unexpectedly.",
            extra={"exception_type": type(exc).__name__},
        )
        raise HTTPException(status_code=503, detail=READINESS_UNAVAILABLE_MESSAGE) from exc
    if not result.ready:
        raise HTTPException(status_code=503, detail=READINESS_UNAVAILABLE_MESSAGE)
    return {"status": "ready"}


@router.get(
    "/metrics",
    response_class=Response,
    responses={
        200: {
            "description": "Prometheus metrics exposition.",
            "content": {"text/plain": {"schema": {"type": "string"}}},
        }
    },
)
def metrics(
    _context: RequestContext = Depends(require_metrics_access()),
) -> PlainTextResponse:
    return PlainTextResponse(
        metrics_collector.render(),
        media_type=PROMETHEUS_CONTENT_TYPE,
    )


@router.post("/claims/extract", response_model=ClaimExtractionResponse)
def extract_claims(
    request: ClaimExtractionRequest,
    _context: RequestContext = Depends(require_endpoint_roles("POST /claims/extract")),
) -> ClaimExtractionResponse:
    return ClaimExtractionResponse(claims=claim_extractor.extract(request))


@router.post("/claims/classify", response_model=ClaimClassificationResponse)
def classify_claims(
    request: ClaimClassificationRequest,
    _context: RequestContext = Depends(require_endpoint_roles("POST /claims/classify")),
) -> ClaimClassificationResponse:
    return ClaimClassificationResponse(
        claims=claim_classifier.classify(request.claims, request.task_type)
    )


@router.post(
    "/evidence/retrieve",
    response_model=EvidenceRetrievalResponse,
    responses={503: {"model": ErrorResponse}},
)
def retrieve_evidence(
    request: EvidenceRetrievalRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /evidence/retrieve")),
) -> EvidenceRetrievalResponse:
    try:
        rag_access_policy.validate_metadata_filter(
            request.metadata_filter,
            tenant_id=context.tenant_id,
        )
        rag_access_policy.validate_retrieval_documents(
            request.documents,
            tenant_id=context.tenant_id,
            principal_roles=context.principal.roles,
        )
        evidence, claim_map = hybrid_retriever.retrieve(
            request.claims,
            request.documents,
            request.max_evidence_per_claim,
            request.metadata_filter,
            tenant_id=context.tenant_id,
            context_refs=request.context_refs,
        )
        evidence, claim_map = rag_access_policy.filter_evidence_for_read(
            evidence,
            claim_map,
            tenant_id=context.tenant_id,
            principal_roles=context.principal.roles,
        )
    except RagAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RagIndexError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return EvidenceRetrievalResponse(evidence=evidence, claim_evidence_map=claim_map)


@router.post(
    "/documents/ingest",
    response_model=DocumentIngestionResponse,
    responses={409: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
)
def ingest_documents(
    request: DocumentIngestionRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /documents/ingest")),
) -> DocumentIngestionResponse:
    try:
        if get_settings().ingestion_mode.strip().lower() == INGESTION_MODE_ASYNC:
            return _enqueue_document_ingestion(request, context)
        return document_ingestor.ingest(
            request,
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            principal_roles=context.principal.roles,
        )
    except RagAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RagIndexError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/documents/ingest/status",
    response_model=DocumentIngestionStatusResponse,
    responses={404: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
)
def document_ingestion_status(
    request: DocumentIngestionStatusRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /documents/ingest/status")),
) -> DocumentIngestionStatusResponse:
    if ingestion_job_queue is None:
        raise HTTPException(
            status_code=503,
            detail="Async ingestion outbox is not configured.",
        )
    try:
        job = ingestion_job_queue.get(job_id=request.job_id, tenant_id=context.tenant_id)
    except (IngestionJobError, PostgresProviderError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if job is None:
        raise HTTPException(
            status_code=404,
            detail="Ingestion job was not found for this tenant.",
        )
    return _job_status_response(job, trace_id=context.trace_id)


def _enqueue_document_ingestion(
    request: DocumentIngestionRequest,
    context: RequestContext,
) -> DocumentIngestionResponse:
    if ingestion_job_queue is None:
        raise HTTPException(
            status_code=503,
            detail="Async ingestion requires the PostgreSQL ingestion outbox.",
        )
    prepared_documents = document_ingestor.prepare_documents(
        request,
        tenant_id=context.tenant_id,
        principal_roles=context.principal.roles,
    )
    try:
        job = ingestion_job_queue.enqueue(
            tenant_id=context.tenant_id,
            corpus_id=request.corpus_id,
            trace_id=context.trace_id,
            job_type=IngestionJobType.INGEST,
            payload={
                "corpus_id": request.corpus_id,
                "documents": [document.model_dump(mode="json") for document in prepared_documents],
            },
        )
    except IngestionTenantDeletedError as exc:
        raise HTTPException(
            status_code=409,
            detail="Tenant deletion fence forbids new ingestion.",
        ) from exc
    except (IngestionJobError, PostgresProviderError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    audit_ledger.append_event(
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
        event_type="ingestion_job_enqueued",
        method="POST",
        path="/documents/ingest",
        status_code=200,
        outcome="queued",
        metadata={
            "job_id": job.job_id,
            "job_type": job.job_type.value,
            "corpus_id": request.corpus_id,
            "document_count": len(request.documents),
        },
    )
    metrics_collector.record_ingestion_job(status=job.status.value)
    return DocumentIngestionResponse(
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
        corpus_id=request.corpus_id,
        backend="async",
        document_count=len(request.documents),
        indexed_count=0,
        evidence_ids=[],
        warnings=["Document ingestion was queued for asynchronous processing."],
        job_id=job.job_id,
        job_status=DocumentIngestionJobStatus(job.status.value),
    )


def _job_status_response(job: IngestionJob, *, trace_id: str) -> DocumentIngestionStatusResponse:
    return DocumentIngestionStatusResponse(
        trace_id=trace_id,
        tenant_id=job.tenant_id,
        job_id=job.job_id,
        corpus_id=job.corpus_id,
        job_type=job.job_type.value,
        job_status=DocumentIngestionJobStatus(job.status.value),
        attempts=job.attempts,
        available_at=job.available_at,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


@router.post("/rag/corpus-grants/upsert", response_model=CorpusGrantResponse)
def upsert_corpus_grant(
    request: CorpusGrantUpsertRequest,
    context: RequestContext = Depends(
        require_endpoint_roles("POST /rag/corpus-grants/upsert", enforce_when_auth_optional=True)
    ),
) -> CorpusGrantResponse:
    try:
        grant = corpus_grant_registry.upsert(
            tenant_id=context.tenant_id,
            request=request,
            updated_by=context.principal.subject_id,
        )
    except CorpusGrantVersionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit_ledger.append_event(
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
        event_type="corpus_grant_upsert",
        method="POST",
        path="/rag/corpus-grants/upsert",
        status_code=200,
        outcome="success",
        metadata={
            "corpus_id": grant.corpus_id,
            "reader_role_count": len(grant.reader_roles),
            "writer_role_count": len(grant.writer_roles),
            "version": grant.version,
            "updated_by": context.principal.subject_id,
        },
    )
    return CorpusGrantResponse(grant=grant)


@router.post("/rag/corpus-grants/disable", response_model=CorpusGrantResponse)
def disable_corpus_grant(
    request: CorpusGrantDisableRequest,
    context: RequestContext = Depends(
        require_endpoint_roles("POST /rag/corpus-grants/disable", enforce_when_auth_optional=True)
    ),
) -> CorpusGrantResponse:
    try:
        grant = corpus_grant_registry.disable(
            tenant_id=context.tenant_id,
            request=request,
            disabled_by=context.principal.subject_id,
        )
    except CorpusGrantNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CorpusGrantVersionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit_ledger.append_event(
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
        event_type="corpus_grant_disable",
        method="POST",
        path="/rag/corpus-grants/disable",
        status_code=200,
        outcome="success",
        metadata={
            "corpus_id": grant.corpus_id,
            "disabled": grant.disabled_at is not None,
            "version": grant.version,
            "updated_by": context.principal.subject_id,
        },
    )
    return CorpusGrantResponse(grant=grant)


@router.post("/rag/corpus-grants/list", response_model=CorpusGrantListResponse)
def list_corpus_grants(
    request: CorpusGrantListRequest,
    context: RequestContext = Depends(
        require_endpoint_roles("POST /rag/corpus-grants/list", enforce_when_auth_optional=True)
    ),
) -> CorpusGrantListResponse:
    try:
        page = corpus_grant_registry.list_for_tenant(context.tenant_id, request)
    except CorpusGrantPaginationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CorpusGrantListResponse(
        grants=page.grants,
        next_cursor=page.next_cursor,
    )


@router.post("/rag/corpus-grants/history", response_model=CorpusGrantHistoryResponse)
def corpus_grant_history(
    request: CorpusGrantHistoryRequest,
    context: RequestContext = Depends(
        require_endpoint_roles("POST /rag/corpus-grants/history", enforce_when_auth_optional=True)
    ),
) -> CorpusGrantHistoryResponse:
    _validate_corpus_grant_history_filters(request)
    try:
        page = corpus_grant_registry.history_for_tenant(context.tenant_id, request)
    except CorpusGrantPaginationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CorpusGrantHistoryResponse(
        grants=page.grants,
        next_cursor=page.next_cursor,
    )


@router.post("/rag/corpus-grants/history/diff", response_model=CorpusGrantHistoryDiffResponse)
def corpus_grant_history_diff(
    request: CorpusGrantHistoryDiffRequest,
    context: RequestContext = Depends(
        require_endpoint_roles(
            "POST /rag/corpus-grants/history/diff",
            enforce_when_auth_optional=True,
        )
    ),
) -> CorpusGrantHistoryDiffResponse:
    _validate_corpus_grant_history_filters(request)
    try:
        page = corpus_grant_registry.history_diffs_for_tenant(context.tenant_id, request)
    except CorpusGrantPaginationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CorpusGrantHistoryDiffResponse(
        diffs=page.diffs,
        next_cursor=page.next_cursor,
    )


def _validate_corpus_grant_history_filters(request: CorpusGrantHistoryRequest) -> None:
    for label, value in (
        ("updated_at_from", request.updated_at_from),
        ("updated_at_to", request.updated_at_to),
    ):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise HTTPException(
                status_code=400,
                detail=f"{label} must include an explicit timezone offset.",
            )
    if (
        request.updated_at_from is not None
        and request.updated_at_to is not None
        and request.updated_at_from > request.updated_at_to
    ):
        raise HTTPException(
            status_code=400,
            detail="updated_at_from must be before or equal to updated_at_to.",
        )


@router.post("/claims/verify", response_model=ClaimVerificationResponse)
def verify_claims(
    request: ClaimVerificationRequest,
    _context: RequestContext = Depends(require_endpoint_roles("POST /claims/verify")),
) -> ClaimVerificationResponse:
    return ClaimVerificationResponse(
        verdicts=claim_verifier.verify(request.claims, request.evidence)
    )


@router.post("/v2/claims/verify", response_model=ClaimVerificationResponseV2)
def verify_claims_v2(
    request: ClaimVerificationRequestV2,
    _context: RequestContext = Depends(require_endpoint_roles("POST /v2/claims/verify")),
) -> ClaimVerificationResponseV2:
    verdicts = claim_verifier.verify(request.claims, request.evidence)
    return ClaimVerificationResponseV2(
        schema_version=V2_SCHEMA_VERSION,
        verdicts=[convert_claim_verdict_v2(verdict) for verdict in verdicts],
    )


@router.post("/response/repair", response_model=ResponseRepairResponse)
def repair_response(
    request: ResponseRepairRequest,
    _context: RequestContext = Depends(require_endpoint_roles("POST /response/repair")),
) -> ResponseRepairResponse:
    return response_repairer.repair(
        request.original_text,
        request.claims,
        request.verdicts,
        request.evidence,
    )


@router.post(
    "/tools/validate-input",
    response_model=ToolValidationResponse,
    responses={503: {"model": ErrorResponse}},
)
def validate_tool_input(
    request: ToolCallEnvelope,
    context: RequestContext = Depends(require_endpoint_roles("POST /tools/validate-input")),
) -> ToolValidationResponse:
    tool_request = _canonical_tool_call(request, context)
    rate_limit_response = _enforce_tool_validation_rate_limit(
        context=context,
        tool_name=tool_request.tool_name,
        phase="input",
    )
    if rate_limit_response is not None:
        return rate_limit_response
    result = tool_safety.validate_input(
        tool_request,
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
    )

    if result.approval_required and (
        tool_request.approval_id is not None or tool_request.approval_execution_token is not None
    ):
        try:
            approval = approval_queue.consume_execution_grant(
                context.tenant_id,
                tool_request,
            )
        except ApprovalNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ApprovalExecutionGrantError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        authorized = tool_safety.validate_input(
            tool_request,
            trace_id=context.trace_id,
            tenant_id=context.tenant_id,
            approval_granted=True,
        )
        if not authorized.allowed:
            return authorized
        return authorized.model_copy(update={"approval_id": approval.approval_id})

    if result.approval_required:
        approval = approval_queue.request_approval(
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            tool_call=tool_request,
            reason=result.reason,
            requested_by=(
                context.principal.subject_id
                if context.principal.is_authenticated
                else str(tool_request.caller_context.get("subject", "system"))
            ),
        )
        metrics_collector.record_approval_request(risk_level=tool_request.risk_level.value)
        return result.model_copy(update={"approval_id": approval.approval_id})
    return result


@router.post("/tools/validate-output", response_model=ToolValidationResponse)
def validate_tool_output(
    request: ToolCallEnvelope,
    context: RequestContext = Depends(require_endpoint_roles("POST /tools/validate-output")),
) -> ToolValidationResponse:
    tool_request = _canonical_tool_call(request, context)
    rate_limit_response = _enforce_tool_validation_rate_limit(
        context=context,
        tool_name=tool_request.tool_name,
        phase="output",
    )
    if rate_limit_response is not None:
        return rate_limit_response
    return tool_safety.validate_output(
        tool_request,
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
    )


@router.post("/policy/evaluate", response_model=PolicyEvaluationResponse)
def evaluate_policy(
    request: PolicyEvaluationRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /policy/evaluate")),
) -> PolicyEvaluationResponse:
    with telemetry.span(
        "policy.evaluate",
        attributes={
            "app.trace_id": context.trace_id,
            "app.component": "policy",
            "policy.risk_level": request.risk_level.value,
        },
    ) as span:
        response = policy_engine.evaluate(
            request, trace_id=context.trace_id, tenant_id=context.tenant_id
        )
        span.set_attribute("policy.allowed", response.allowed)
        span.set_attribute("policy.action", response.action.value)
        span.set_attribute("policy.matched_rule_count", len(response.matched_rules))
        span.set_attribute("app.outcome", "success")
        return response


@router.post("/approvals/list", response_model=ApprovalListResponse)
def list_approvals(
    request: ApprovalListRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /approvals/list")),
) -> ApprovalListResponse:
    return ApprovalListResponse(
        approvals=approval_queue.list_for_tenant(context.tenant_id, request)
    )


@router.post("/approvals/decide", response_model=ApprovalDecisionResponse)
def decide_approval(
    request: ApprovalDecisionRequest,
    context: RequestContext = Depends(
        require_endpoint_roles("POST /approvals/decide", enforce_when_auth_optional=True)
    ),
) -> ApprovalDecisionResponse:
    reviewer_request = request.model_copy(update={"decided_by": context.principal.subject_id})
    try:
        result = approval_queue.decide_with_grant(context.tenant_id, reviewer_request)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalAlreadyDecidedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    metrics_collector.record_approval_decision(
        decision=reviewer_request.decision.value,
        status=result.approval.status.value,
        risk_level=result.approval.risk_level.value,
    )
    return ApprovalDecisionResponse(
        approval=result.approval,
        execution_grant=result.execution_grant,
    )


@router.post("/repo/checks/run", response_model=SandboxRun)
def run_repo_checks(
    request: RepoChecksRunRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /repo/checks/run")),
    runtime_settings: Settings = Depends(get_settings),
) -> SandboxRun:
    if (
        runtime_settings.sandbox_backend == "kubernetes"
        and context.tenant_id != runtime_settings.sandbox_kubernetes_tenant_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Kubernetes sandbox workspace is bound to a different tenant",
        )
    started_at = time.perf_counter()
    with telemetry.span(
        "sandbox.run",
        attributes={
            "app.trace_id": context.trace_id,
            "app.component": "sandbox",
            "sandbox.command_count": len(request.commands),
            "sandbox.network_policy": request.network_policy,
        },
    ) as span:
        try:
            run = sandbox_runner.run(request)
        except SandboxError as exc:
            span.set_attribute("sandbox.outcome", "error")
            span.set_attribute("app.outcome", "error")
            metrics_collector.record_sandbox_run(
                verdict="ERROR",
                network_policy=request.network_policy,
                outcome="error",
                duration_seconds=time.perf_counter() - started_at,
            )
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        span.set_attribute("sandbox.outcome", "completed")
        span.set_attribute("sandbox.verdict", run.verdict.value)
        span.set_attribute("app.outcome", "success")
        metrics_collector.record_sandbox_run(
            verdict=run.verdict.value,
            network_policy=run.network_policy,
            outcome="completed",
            duration_seconds=time.perf_counter() - started_at,
        )
        return run


@router.post(
    "/audit/export",
    response_model=AuditExportResponse,
    responses={503: {"model": ErrorResponse}},
)
def export_audit(
    request: AuditExportRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /audit/export")),
) -> AuditExportResponse:
    tenant_id = _authenticated_tenant_id(request.tenant_id, context)
    try:
        snapshot = audit_ledger.export_snapshot(
            tenant_id=tenant_id,
            trace_id=request.trace_id,
            include_events=request.include_events,
        )
    except (AuditLedgerError, PostgresProviderError) as exc:
        LOGGER.error(
            "audit export snapshot read failed",
            extra={
                "trace_id": context.trace_id,
                "exception_type": type(exc).__name__,
            },
        )
        raise HTTPException(
            status_code=503,
            detail=AUDIT_HISTORY_UNAVAILABLE_MESSAGE,
        ) from exc
    return AuditExportResponse(
        trace_id=context.trace_id,
        runs=list(snapshot.runs),
        events=list(snapshot.events),
    )


@router.post("/evals/reports/publish", response_model=EvalReportPublishResponse)
def publish_eval_report(
    request: EvalReportPublishRequest,
    context: RequestContext = Depends(
        require_endpoint_roles(
            "POST /evals/reports/publish",
            enforce_when_auth_optional=True,
        )
    ),
) -> EvalReportPublishResponse:
    report = eval_report_repository.publish(
        tenant_id=context.tenant_id,
        request=request,
        published_by=context.principal.subject_id,
    )
    metrics_collector.record_eval_report(
        suite=report.suite,
        pass_rate=report.metrics.pass_rate,
        p95_latency_ms=report.metrics.p95_latency_ms,
        scenario_count=report.metrics.scenario_count,
        groundedness=report.metrics.groundedness,
        faithfulness=report.metrics.faithfulness,
    )
    audit_ledger.append_event(
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
        event_type="eval_report_published",
        method="POST",
        path="/evals/reports/publish",
        status_code=200,
        outcome="success",
        metadata={
            "report_id": report.report_id,
            "suite": report.suite,
            "run_id": report.run_id,
            "scenario_count": report.metrics.scenario_count,
            "published_by": context.principal.subject_id,
        },
    )
    return EvalReportPublishResponse(trace_id=context.trace_id, report=report)


@router.post("/evals/reports/list", response_model=EvalReportListResponse)
def list_eval_reports(
    request: EvalReportListRequest,
    context: RequestContext = Depends(
        require_endpoint_roles(
            "POST /evals/reports/list",
            enforce_when_auth_optional=True,
        )
    ),
) -> EvalReportListResponse:
    return EvalReportListResponse(
        trace_id=context.trace_id,
        reports=eval_report_repository.list_for_tenant(
            tenant_id=context.tenant_id,
            request=request,
        ),
    )


@router.post(
    "/verification/runs/list",
    response_model=VerificationRunListResponse,
    responses={400: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
)
def list_verification_runs(
    request: VerificationRunListRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /verification/runs/list")),
) -> VerificationRunListResponse:
    try:
        runs, next_cursor = list_verification_history(
            audit_ledger,
            tenant_id=context.tenant_id,
            request=request,
        )
    except VerificationHistoryCursorError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (VerificationHistoryIntegrityError, AuditLedgerError, PostgresProviderError) as exc:
        LOGGER.error(
            "verification history integrity check failed",
            extra={"trace_id": context.trace_id},
        )
        raise HTTPException(
            status_code=503,
            detail="Verification history is unavailable.",
        ) from exc
    return VerificationRunListResponse(
        trace_id=context.trace_id,
        runs=runs,
        next_cursor=next_cursor,
    )


@router.post(
    "/verification/run",
    response_model=VerificationRun,
    responses={503: {"model": ErrorResponse}},
)
def run_verification(
    request: VerificationRunRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /verification/run")),
) -> VerificationRun:
    tenant_request = request.model_copy(
        update={"tenant_id": _authenticated_tenant_id(request.tenant_id, context)}
    )
    run = orchestrator.run(tenant_request)
    return _record_verification_completed(
        run,
        path="/verification/run",
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
    )


@router.post(
    "/v2/verification/run",
    response_model=VerificationRunV2,
    responses={503: {"model": ErrorResponse}},
)
def run_verification_v2(
    request: VerificationRunRequestV2,
    context: RequestContext = Depends(require_endpoint_roles("POST /v2/verification/run")),
) -> VerificationRunV2:
    legacy_request = convert_verification_request_v1(request).model_copy(
        update={"tenant_id": _authenticated_tenant_id(request.tenant_id, context)}
    )
    run = orchestrator.run(legacy_request)
    # Validate the public v2 envelope before committing a successful completion.
    convert_verification_run_v2(run)
    persisted_run = _record_verification_completed(
        run,
        path="/v2/verification/run",
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
    )
    return convert_verification_run_v2(persisted_run)


@router.post(
    "/verification/replay",
    response_model=VerificationReplayResponse,
    responses={409: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
)
def replay_verification(
    request: VerificationReplayRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /verification/replay")),
) -> VerificationReplayResponse:
    try:
        source = audit_ledger.find_replay_source(
            tenant_id=context.tenant_id,
            trace_id=request.trace_id,
        )
    except ReplaySourceConflictError as exc:
        LOGGER.warning(
            "verification replay source is ambiguous",
            extra={"exception_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=409,
            detail=VERIFICATION_REPLAY_SOURCE_CONFLICT_MESSAGE,
        ) from exc
    except (AuditLedgerError, PostgresProviderError) as exc:
        LOGGER.error(
            "verification replay source persistence read failed",
            extra={"exception_type": type(exc).__name__},
        )
        raise HTTPException(
            status_code=503,
            detail=VERIFICATION_PERSISTENCE_UNAVAILABLE_MESSAGE,
        ) from exc
    if source is None:
        raise HTTPException(
            status_code=404,
            detail="Verification run was not found for this tenant.",
        )
    replayed_run = orchestrator.replay(source)
    decision_changed = replayed_run.final_decision != source.final_decision
    # Construct the response once before persistence so response-model errors
    # cannot leave a committed completion behind.
    response = VerificationReplayResponse(
        trace_id=context.trace_id,
        source_trace_id=source.trace_id,
        source_created_at=source.created_at,
        source_final_decision=source.final_decision,
        decision_changed=decision_changed,
        replayed_run=replayed_run,
    )
    replayed_run = _record_verification_completed(
        replayed_run,
        path="/verification/replay",
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
        source_trace_id=source.trace_id,
        source_final_decision=source.final_decision,
    )
    if replayed_run is response.replayed_run:
        return response
    return response.model_copy(update={"replayed_run": replayed_run})
