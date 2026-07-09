from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status

from hallu_defense import __version__
from hallu_defense.config import (
    AUTH_CLAIMS_MODE_OIDC_JWT,
    INGESTION_MODE_ASYNC,
    Settings,
    load_settings,
)
from hallu_defense.services import (
    ClaimClassifier,
    ClaimExtractor,
    ClaimVerifier,
    ContentSecurityScanner,
    DocumentIngestionService,
    HybridRetriever,
    OpaPolicyEvaluator,
    PolicyEngine,
    PostgresIngestionJobQueue,
    PrometheusMetrics,
    RagAccessPolicy,
    ModelProvider,
    create_rag_index_backend,
    create_nli_adjudicator,
    create_approval_queue,
    create_audit_ledger,
    create_corpus_grant_registry,
    ResponseRepairer,
    SandboxRunner,
    SecretManager,
    TelemetryService,
    ToolValidationRateLimiter,
    ToolSafetyService,
    VerificationOrchestrator,
    build_sandbox_execution_backend,
    create_eval_report_repository,
    create_ingestion_job_queue,
    create_model_provider,
    create_secret_manager,
)
from hallu_defense.services.auth import (
    APPROVAL_REVIEWER_ROLE,
    AUDITOR_ROLE,
    EVAL_PUBLISHER_ROLE,
    METRICS_READER_ROLE,
    POLICY_EVALUATOR_ROLE,
    RAG_WRITER_ROLE,
    SANDBOX_RUNNER_ROLE,
    TOOL_OPERATOR_ROLE,
    VERIFIER_ROLE,
    AuthenticationError,
    AuthorizationError,
    Principal,
    principal_from_headers,
)
from hallu_defense.services.postgres import build_postgres_provider
from hallu_defense.services.secrets import SecretAccessError, SecretConfigurationError, SecretNotFoundError
from hallu_defense.services.oidc import (
    OidcJwksKeyNotFoundError,
    OidcJwksResolver,
    OidcPrincipalClaims,
    OidcJwtValidationError,
    OidcJwtValidator,
)
from hallu_defense.services.trace import current_trace_id


@dataclass(frozen=True)
class RequestContext:
    tenant_id: str
    trace_id: str
    principal: Principal


ENDPOINT_ROLE_REQUIREMENTS: dict[str, frozenset[str]] = {
    "GET /metrics": frozenset({METRICS_READER_ROLE}),
    "POST /claims/extract": frozenset({VERIFIER_ROLE}),
    "POST /claims/classify": frozenset({VERIFIER_ROLE}),
    "POST /evidence/retrieve": frozenset({VERIFIER_ROLE}),
    "POST /documents/ingest": frozenset({RAG_WRITER_ROLE}),
    "POST /documents/ingest/status": frozenset({RAG_WRITER_ROLE}),
    "POST /rag/corpus-grants/upsert": frozenset({RAG_WRITER_ROLE}),
    "POST /rag/corpus-grants/disable": frozenset({RAG_WRITER_ROLE}),
    "POST /rag/corpus-grants/list": frozenset({RAG_WRITER_ROLE, VERIFIER_ROLE}),
    "POST /rag/corpus-grants/history": frozenset({RAG_WRITER_ROLE, VERIFIER_ROLE}),
    "POST /rag/corpus-grants/history/diff": frozenset({RAG_WRITER_ROLE, VERIFIER_ROLE}),
    "POST /claims/verify": frozenset({VERIFIER_ROLE}),
    "POST /response/repair": frozenset({VERIFIER_ROLE}),
    "POST /tools/validate-input": frozenset({TOOL_OPERATOR_ROLE}),
    "POST /tools/validate-output": frozenset({TOOL_OPERATOR_ROLE}),
    "POST /policy/evaluate": frozenset({POLICY_EVALUATOR_ROLE}),
    "POST /approvals/list": frozenset({APPROVAL_REVIEWER_ROLE}),
    "POST /approvals/decide": frozenset({APPROVAL_REVIEWER_ROLE}),
    "POST /repo/checks/run": frozenset({SANDBOX_RUNNER_ROLE}),
    "POST /audit/export": frozenset({AUDITOR_ROLE}),
    "POST /evals/reports/publish": frozenset({EVAL_PUBLISHER_ROLE}),
    "POST /evals/reports/list": frozenset({AUDITOR_ROLE, VERIFIER_ROLE}),
    "POST /verification/run": frozenset({VERIFIER_ROLE}),
    "POST /verification/replay": frozenset({VERIFIER_ROLE}),
}


settings = load_settings()
_oidc_resolver_settings: Settings | None = None
_oidc_resolver: OidcJwksResolver | None = None
telemetry = TelemetryService.from_settings(settings)
secret_manager = create_secret_manager(settings)
model_provider = create_model_provider(settings, secret_manager)
nli_adjudicator = create_nli_adjudicator(settings, model_provider)
rag_index_backend = create_rag_index_backend(settings)
_POSTGRES_BACKENDS = {"postgres", "postgresql"}
_needs_pg = (
    settings.audit_ledger_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.approval_queue_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.eval_reports_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.ingestion_mode.strip().lower() == INGESTION_MODE_ASYNC
)
_sql_provider = build_postgres_provider(settings) if _needs_pg else None
audit_ledger = create_audit_ledger(settings, sql_provider=_sql_provider)
approval_queue = create_approval_queue(settings, sql_provider=_sql_provider)
eval_report_repository = create_eval_report_repository(settings, sql_provider=_sql_provider)
ingestion_job_queue: PostgresIngestionJobQueue | None = (
    create_ingestion_job_queue(settings, sql_provider=_sql_provider)
    if settings.ingestion_mode.strip().lower() == INGESTION_MODE_ASYNC
    else None
)
corpus_grant_registry = create_corpus_grant_registry(settings)
claim_extractor = ClaimExtractor()
claim_classifier = ClaimClassifier()
content_security_scanner = ContentSecurityScanner()
hybrid_retriever = HybridRetriever(
    index_backend=rag_index_backend,
    content_scanner=content_security_scanner,
)
rag_access_policy = RagAccessPolicy(corpus_grant_registry=corpus_grant_registry)
document_ingestor = DocumentIngestionService(hybrid_retriever, access_policy=rag_access_policy)
claim_verifier = ClaimVerifier(nli_adjudicator=nli_adjudicator)
response_repairer = ResponseRepairer()
opa_policy_evaluator = OpaPolicyEvaluator(settings)
metrics_collector = PrometheusMetrics(
    service_name="hallu-defense-api",
    service_version=__version__,
    environment=settings.environment,
)
policy_engine = PolicyEngine(settings, opa_evaluator=opa_policy_evaluator, metrics=metrics_collector)
tool_safety = ToolSafetyService()
tool_validation_rate_limiter = ToolValidationRateLimiter(
    max_requests=settings.tool_validation_rate_limit_max_requests,
    window_seconds=settings.tool_validation_rate_limit_window_seconds,
)
sandbox_execution_backend = build_sandbox_execution_backend(settings)
sandbox_runner = SandboxRunner(settings, execution_backend=sandbox_execution_backend)
orchestrator = VerificationOrchestrator(
    settings=settings,
    audit=audit_ledger,
    extractor=claim_extractor,
    classifier=claim_classifier,
    retriever=hybrid_retriever,
    verifier=claim_verifier,
    repairer=response_repairer,
    metrics=metrics_collector,
    telemetry=telemetry,
    policy_engine=policy_engine,
    content_scanner=content_security_scanner,
)


def get_settings() -> Settings:
    return settings


def get_secret_manager() -> SecretManager:
    return secret_manager


def get_model_provider() -> ModelProvider:
    return model_provider


def get_request_context(
    request: Request,
    x_tenant_id: str | None = Header(default=None),
    x_subject_id: str | None = Header(default=None),
    x_roles: str | None = Header(default=None),
    x_auth_claims_signature: str | None = Header(default=None),
    x_auth_claims_timestamp: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> RequestContext:
    tenant_id = x_tenant_id or "local-dev"
    if settings.auth_claims_mode == AUTH_CLAIMS_MODE_OIDC_JWT:
        try:
            claims = _validate_oidc_claims(authorization)
        except OidcJwtValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc
        if x_tenant_id is not None and x_tenant_id != claims.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tenant header does not match OIDC token tenant claim.",
            )
        request.state.authenticated_tenant_id = claims.tenant_id
        return RequestContext(
            tenant_id=claims.tenant_id,
            trace_id=current_trace_id(),
            principal=claims.principal,
        )

    try:
        principal = principal_from_headers(
            tenant_id=tenant_id,
            subject_id=x_subject_id,
            roles_header=x_roles,
            authorization=authorization,
            auth_required=settings.auth_required,
            claims_mode=settings.auth_claims_mode,
            claims_signature=x_auth_claims_signature,
            claims_timestamp=x_auth_claims_timestamp,
            signature_secret=_auth_claims_signature_secret(),
            signature_tolerance_seconds=settings.auth_claims_signature_tolerance_seconds,
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
    request.state.authenticated_tenant_id = tenant_id
    return RequestContext(
        tenant_id=tenant_id,
        trace_id=current_trace_id(),
        principal=principal,
    )


def require_roles(
    *roles: str,
    enforce_when_auth_optional: bool = False,
) -> Callable[[RequestContext], RequestContext]:
    required_roles = frozenset(roles)
    if not required_roles:
        raise ValueError("At least one role is required.")

    def dependency(context: RequestContext = Depends(get_request_context)) -> RequestContext:
        if not settings.auth_required and not enforce_when_auth_optional:
            return context
        try:
            context.principal.require_any_role(required_roles)
        except AuthorizationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return context

    return dependency


def require_endpoint_roles(
    endpoint: str,
    *,
    enforce_when_auth_optional: bool = False,
) -> Callable[[RequestContext], RequestContext]:
    try:
        roles = ENDPOINT_ROLE_REQUIREMENTS[endpoint]
    except KeyError as exc:
        raise ValueError(f"No RBAC role requirement configured for endpoint {endpoint!r}.") from exc
    return require_roles(*roles, enforce_when_auth_optional=enforce_when_auth_optional)


METRICS_BEARER_TOKEN_SUBJECT = "metrics-scraper"


def require_metrics_access() -> Callable[..., RequestContext]:
    def dependency(
        request: Request,
        x_tenant_id: str | None = Header(default=None),
        x_subject_id: str | None = Header(default=None),
        x_roles: str | None = Header(default=None),
        x_auth_claims_signature: str | None = Header(default=None),
        x_auth_claims_timestamp: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> RequestContext:
        if _metrics_bearer_token_matches(authorization):
            tenant_id = x_tenant_id or "local-dev"
            request.state.authenticated_tenant_id = tenant_id
            return RequestContext(
                tenant_id=tenant_id,
                trace_id=current_trace_id(),
                principal=Principal(
                    subject_id=METRICS_BEARER_TOKEN_SUBJECT,
                    roles=frozenset({METRICS_READER_ROLE}),
                ),
            )

        context = get_request_context(
            request=request,
            x_tenant_id=x_tenant_id,
            x_subject_id=x_subject_id,
            x_roles=x_roles,
            x_auth_claims_signature=x_auth_claims_signature,
            x_auth_claims_timestamp=x_auth_claims_timestamp,
            authorization=authorization,
        )
        if not settings.auth_required:
            return context
        try:
            context.principal.require_any_role(frozenset({METRICS_READER_ROLE}))
        except AuthorizationError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        return context

    return dependency


def _metrics_bearer_token_matches(authorization: str | None) -> bool:
    secret_name = settings.metrics_bearer_token_secret_name
    if secret_name is None or not secret_name.strip():
        return False
    token = _bearer_token(authorization)
    if token is None:
        return False
    try:
        expected = secret_manager.get_secret(secret_name.strip()).reveal()
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError):
        return False
    if not expected:
        return False
    return hmac.compare_digest(token, expected)


def _bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    prefix = "bearer "
    if not authorization.lower().startswith(prefix):
        return None
    token = authorization[len(prefix) :].strip()
    return token or None


def _auth_claims_signature_secret() -> str | None:
    if settings.auth_claims_mode != "signed_headers":
        return None
    try:
        return secret_manager.get_secret(settings.auth_claims_signature_secret_name).reveal()
    except (SecretAccessError, SecretConfigurationError, SecretNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication claims signing secret is not configured.",
        ) from exc


def _validate_oidc_claims(authorization: str | None) -> OidcPrincipalClaims:
    try:
        return OidcJwtValidator(settings, _oidc_jwks()).validate(authorization)
    except OidcJwksKeyNotFoundError:
        return OidcJwtValidator(settings, _oidc_jwks(force_refresh=True)).validate(authorization)


def _oidc_jwks(*, force_refresh: bool = False) -> dict[str, object]:
    resolver = _oidc_jwks_resolver()
    try:
        return dict(resolver.resolve(force_refresh=force_refresh))
    except OidcJwtValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC JWKS configuration is invalid.",
        ) from exc


def _oidc_jwks_resolver() -> OidcJwksResolver:
    global _oidc_resolver, _oidc_resolver_settings
    if _oidc_resolver is None or _oidc_resolver_settings is not settings:
        _oidc_resolver = OidcJwksResolver(settings)
        _oidc_resolver_settings = settings
    return _oidc_resolver
