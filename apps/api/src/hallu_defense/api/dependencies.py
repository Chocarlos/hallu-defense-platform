from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.routing import APIRoute

from hallu_defense import __version__
from hallu_defense.config import (
    AUTH_CLAIMS_MODE_OIDC_JWT,
    INGESTION_MODE_ASYNC,
    RUNTIME_ROLE_API,
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
    ReadinessService,
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
    ToolSafetyService,
    VerificationOrchestrator,
    build_sandbox_execution_backend,
    create_eval_report_repository,
    create_ingestion_job_queue,
    create_model_provider,
    create_readiness_service,
    create_secret_manager,
    create_tool_validation_rate_limiter,
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
from hallu_defense.services.secret_token import RotatingSecretTokenVerifier
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
    "POST /v2/claims/verify": frozenset({VERIFIER_ROLE}),
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
    "POST /verification/runs/list": frozenset({AUDITOR_ROLE, VERIFIER_ROLE}),
    "POST /verification/run": frozenset({VERIFIER_ROLE}),
    "POST /v2/verification/run": frozenset({VERIFIER_ROLE}),
    "POST /verification/replay": frozenset({VERIFIER_ROLE}),
}
PUBLIC_PROBE_ROUTES = frozenset({"GET /health", "GET /ready"})
_AUTH_DEPENDENCY_MARKER = "__hallu_auth_dependency__"
_AUTH_ENDPOINT_MARKER = "__hallu_endpoint_key__"
_AUTH_ROLES_MARKER = "__hallu_required_roles__"


settings = load_settings(expected_runtime_role=RUNTIME_ROLE_API)
_oidc_resolver_settings: Settings | None = None
_oidc_resolver: OidcJwksResolver | None = None
telemetry = TelemetryService.from_settings(settings)
secret_manager = create_secret_manager(settings)
tool_validation_rate_limiter = create_tool_validation_rate_limiter(settings, secret_manager)
rag_index_backend = create_rag_index_backend(settings, secret_manager)
readiness_service = create_readiness_service(
    settings,
    secret_manager,
    tool_validation_rate_limiter=tool_validation_rate_limiter,
    rag_index_backend=rag_index_backend,
)
metrics_collector = PrometheusMetrics(
    service_name="hallu-defense-api",
    service_version=__version__,
    environment=settings.environment,
)
model_provider = create_model_provider(settings, secret_manager)
nli_adjudicator = create_nli_adjudicator(
    settings,
    model_provider,
    observer=metrics_collector,
)
_POSTGRES_BACKENDS = {"postgres", "postgresql"}
_needs_pg = (
    settings.audit_ledger_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.approval_queue_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.corpus_grants_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.eval_reports_backend.strip().lower() in _POSTGRES_BACKENDS
    or settings.ingestion_mode.strip().lower() == INGESTION_MODE_ASYNC
)
_sql_provider = build_postgres_provider(settings) if _needs_pg else None
audit_ledger = create_audit_ledger(settings, sql_provider=_sql_provider)
approval_queue = create_approval_queue(
    settings,
    sql_provider=_sql_provider,
    secret_manager=secret_manager,
)
eval_report_repository = create_eval_report_repository(settings, sql_provider=_sql_provider)
ingestion_job_queue: PostgresIngestionJobQueue | None = (
    create_ingestion_job_queue(settings, sql_provider=_sql_provider)
    if settings.ingestion_mode.strip().lower() == INGESTION_MODE_ASYNC
    else None
)
corpus_grant_registry = create_corpus_grant_registry(
    settings,
    postgres_connection=_sql_provider,
)
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
policy_engine = PolicyEngine(settings, opa_evaluator=opa_policy_evaluator, metrics=metrics_collector)
tool_safety = ToolSafetyService(
    policy_engine=policy_engine,
    content_scanner=content_security_scanner,
)
sandbox_execution_backend = build_sandbox_execution_backend(settings)
sandbox_runner = SandboxRunner(settings, execution_backend=sandbox_execution_backend)
orchestrator = VerificationOrchestrator(
    settings=settings,
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


def get_readiness_service() -> ReadinessService:
    return readiness_service


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
    dependency = require_roles(*roles, enforce_when_auth_optional=enforce_when_auth_optional)
    return _brand_auth_dependency(dependency, endpoint=endpoint, roles=roles)


METRICS_BEARER_TOKEN_SUBJECT = "metrics-scraper"
_metrics_token_verifier: RotatingSecretTokenVerifier | None = None
_metrics_token_verifier_source: tuple[int, str] | None = None
_metrics_token_verifier_lock = threading.Lock()


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

    return _brand_auth_dependency(
        dependency,
        endpoint="GET /metrics",
        roles=ENDPOINT_ROLE_REQUIREMENTS["GET /metrics"],
    )


def _brand_auth_dependency(
    dependency: Callable[..., RequestContext],
    *,
    endpoint: str,
    roles: frozenset[str],
) -> Callable[..., RequestContext]:
    setattr(dependency, _AUTH_DEPENDENCY_MARKER, True)
    setattr(dependency, _AUTH_ENDPOINT_MARKER, endpoint)
    setattr(dependency, _AUTH_ROLES_MARKER, roles)
    return dependency


def validate_endpoint_auth_coverage(route_objects: Sequence[object]) -> None:
    """Fail closed when any business route lacks its exact RBAC dependency."""

    errors: list[str] = []
    seen: set[str] = set()
    for route in route_objects:
        if not isinstance(route, APIRoute):
            continue
        methods = sorted(
            method
            for method in (route.methods or set())
            if method not in {"HEAD", "OPTIONS"}
        )
        if len(methods) != 1:
            errors.append(
                f"route {route.path!r} must expose exactly one auditable HTTP method"
            )
            continue
        endpoint = f"{methods[0]} {route.path}"
        branded = [
            dependency.call
            for dependency in route.dependant.dependencies
            if dependency.call is not None
            and getattr(dependency.call, _AUTH_DEPENDENCY_MARKER, False) is True
        ]
        if endpoint in PUBLIC_PROBE_ROUTES:
            if branded:
                errors.append(f"public probe {endpoint} must not carry a business RBAC marker")
            continue
        expected_roles = ENDPOINT_ROLE_REQUIREMENTS.get(endpoint)
        if expected_roles is None:
            errors.append(f"business route {endpoint} has no RBAC role requirement")
            continue
        if endpoint in seen:
            errors.append(f"business route {endpoint} is registered more than once")
        seen.add(endpoint)
        if len(branded) != 1:
            errors.append(
                f"business route {endpoint} must carry exactly one branded auth dependency"
            )
            continue
        dependency = branded[0]
        if getattr(dependency, _AUTH_ENDPOINT_MARKER, None) != endpoint:
            errors.append(f"business route {endpoint} auth dependency targets another endpoint")
        if getattr(dependency, _AUTH_ROLES_MARKER, None) != expected_roles:
            errors.append(f"business route {endpoint} auth dependency has incorrect roles")

    orphaned = set(ENDPOINT_ROLE_REQUIREMENTS).difference(seen)
    if orphaned:
        errors.append(
            "RBAC role matrix contains orphaned endpoints: " + ", ".join(sorted(orphaned))
        )
    if errors:
        raise RuntimeError("; ".join(errors))


def _metrics_bearer_token_matches(authorization: str | None) -> bool:
    secret_name = settings.metrics_bearer_token_secret_name
    if secret_name is None or not secret_name.strip():
        return False
    token = _bearer_token(authorization)
    if token is None:
        return False
    return _metrics_bearer_token_verifier(secret_name.strip()).matches(token)


def _metrics_bearer_token_verifier(secret_name: str) -> RotatingSecretTokenVerifier:
    global _metrics_token_verifier, _metrics_token_verifier_source
    source = (id(secret_manager), secret_name)
    with _metrics_token_verifier_lock:
        if _metrics_token_verifier is None or _metrics_token_verifier_source != source:
            _metrics_token_verifier = RotatingSecretTokenVerifier(
                secret_manager,
                secret_name=secret_name,
            )
            _metrics_token_verifier_source = source
        return _metrics_token_verifier


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
    except OidcJwksKeyNotFoundError as exc:
        resolver = _oidc_jwks_resolver()
        try:
            refreshed = resolver.resolve_unknown_kid(exc.kid)
        except OidcJwtValidationError as refresh_error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="OIDC JWKS configuration is invalid.",
            ) from refresh_error
        return OidcJwtValidator(settings, refreshed).validate(authorization)


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
