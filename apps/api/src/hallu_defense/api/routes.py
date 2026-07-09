from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response

from hallu_defense.api.dependencies import (
    RequestContext,
    approval_queue,
    audit_ledger,
    claim_classifier,
    claim_extractor,
    claim_verifier,
    corpus_grant_registry,
    document_ingestor,
    get_settings,
    hybrid_retriever,
    metrics_collector,
    orchestrator,
    policy_engine,
    rag_access_policy,
    require_endpoint_roles,
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
    CorpusGrantDisableRequest,
    CorpusGrantHistoryDiffRequest,
    CorpusGrantHistoryDiffResponse,
    CorpusGrantHistoryRequest,
    CorpusGrantHistoryResponse,
    CorpusGrantListRequest,
    CorpusGrantListResponse,
    CorpusGrantResponse,
    CorpusGrantUpsertRequest,
    DocumentIngestionRequest,
    DocumentIngestionResponse,
    EvidenceRetrievalRequest,
    EvidenceRetrievalResponse,
    ErrorResponse,
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
    VerificationRunRequest,
    VerdictAction,
)
from hallu_defense.services.approvals import (
    ApprovalAlreadyDecidedError,
    ApprovalExecutionGrantError,
    ApprovalNotFoundError,
)
from hallu_defense.services.corpus_grants import (
    CorpusGrantNotFoundError,
    CorpusGrantPaginationError,
    CorpusGrantVersionConflictError,
)
from hallu_defense.services.metrics import PROMETHEUS_CONTENT_TYPE
from hallu_defense.services.rag_access import RagAccessDeniedError
from hallu_defense.services.rag_index import RagIndexError
from hallu_defense.services.sandbox import SandboxError

ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse},
    401: {"model": ErrorResponse},
    403: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
    409: {"model": ErrorResponse},
    422: {"model": ErrorResponse},
    500: {"model": ErrorResponse},
}

router = APIRouter(responses=ERROR_RESPONSES)


@router.get("/health")
def health() -> dict[str, str]:
    settings = get_settings()
    return {"status": "ok", "environment": settings.environment}


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
    _context: RequestContext = Depends(require_endpoint_roles("GET /metrics")),
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
    responses={503: {"model": ErrorResponse}},
)
def ingest_documents(
    request: DocumentIngestionRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /documents/ingest")),
) -> DocumentIngestionResponse:
    try:
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
    return ClaimVerificationResponse(verdicts=claim_verifier.verify(request.claims, request.evidence))


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


@router.post("/tools/validate-input", response_model=ToolValidationResponse)
def validate_tool_input(
    request: ToolCallEnvelope,
    context: RequestContext = Depends(require_endpoint_roles("POST /tools/validate-input")),
) -> ToolValidationResponse:
    result = tool_safety.validate_input(request)
    if result.approval_required and (
        request.approval_id is not None or request.approval_execution_token is not None
    ):
        try:
            approval = approval_queue.consume_execution_grant(context.tenant_id, request)
        except ApprovalNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ApprovalExecutionGrantError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return ToolValidationResponse(
            allowed=True,
            action=VerdictAction.ALLOW,
            reason="Tool call was authorized by an approved execution grant.",
            approval_required=False,
            approval_id=approval.approval_id,
        )

    if not tool_validation_rate_limiter.allow(
        tenant_id=context.tenant_id,
        subject_id=context.principal.subject_id,
        tool_name=request.tool_name,
    ):
        return ToolValidationResponse(
            allowed=False,
            action=VerdictAction.BLOCK,
            reason="Tool validation rate limit exceeded.",
            approval_required=False,
        )

    if result.approval_required:
        approval = approval_queue.request_approval(
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            tool_call=request,
            reason=result.reason,
            requested_by=str(request.caller_context.get("subject", "system")),
        )
        metrics_collector.record_approval_request(risk_level=request.risk_level.value)
        return result.model_copy(update={"approval_id": approval.approval_id})
    return result


@router.post("/tools/validate-output", response_model=ToolValidationResponse)
def validate_tool_output(
    request: ToolCallEnvelope,
    _context: RequestContext = Depends(require_endpoint_roles("POST /tools/validate-output")),
) -> ToolValidationResponse:
    return tool_safety.validate_output(request)


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
        response = policy_engine.evaluate(request, trace_id=context.trace_id, tenant_id=context.tenant_id)
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
    return ApprovalListResponse(approvals=approval_queue.list_for_tenant(context.tenant_id, request))


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
) -> SandboxRun:
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


@router.post("/audit/export", response_model=AuditExportResponse)
def export_audit(
    request: AuditExportRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /audit/export")),
) -> AuditExportResponse:
    tenant_id = request.tenant_id or context.tenant_id
    return AuditExportResponse(
        trace_id=context.trace_id,
        runs=audit_ledger.export(tenant_id=tenant_id, trace_id=request.trace_id),
        events=audit_ledger.export_events(tenant_id=tenant_id, trace_id=request.trace_id)
        if request.include_events
        else [],
    )


@router.post("/verification/run", response_model=VerificationRun)
def run_verification(
    request: VerificationRunRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /verification/run")),
) -> VerificationRun:
    tenant_request = request.model_copy(update={"tenant_id": request.tenant_id or context.tenant_id})
    return orchestrator.run(tenant_request)


@router.post("/verification/replay", response_model=VerificationReplayResponse)
def replay_verification(
    request: VerificationReplayRequest,
    context: RequestContext = Depends(require_endpoint_roles("POST /verification/replay")),
) -> VerificationReplayResponse:
    source_runs = audit_ledger.export(tenant_id=context.tenant_id, trace_id=request.trace_id)
    source_candidates = [run for run in source_runs if not isinstance(run.input.get("replay_of"), str)]
    if not source_candidates:
        raise HTTPException(
            status_code=404,
            detail="Verification run was not found for this tenant.",
        )
    source = source_candidates[-1]
    replayed_run = orchestrator.replay(source)
    decision_changed = replayed_run.final_decision != source.final_decision
    audit_ledger.append_event(
        trace_id=context.trace_id,
        tenant_id=context.tenant_id,
        event_type="verification_replay",
        method="POST",
        path="/verification/replay",
        status_code=200,
        outcome="success",
        metadata={
            "source_trace_id": source.trace_id,
            "source_final_decision": source.final_decision.value,
            "replay_final_decision": replayed_run.final_decision.value,
            "decision_changed": decision_changed,
        },
    )
    return VerificationReplayResponse(
        trace_id=context.trace_id,
        source_trace_id=source.trace_id,
        source_created_at=source.created_at,
        source_final_decision=source.final_decision,
        decision_changed=decision_changed,
        replayed_run=replayed_run,
    )
