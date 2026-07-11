from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware

from hallu_defense import __version__
from hallu_defense.api.dependencies import get_settings, validate_endpoint_auth_coverage
from hallu_defense.api.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from hallu_defense.api.middleware import (
    RequestBodyLimitMiddleware,
    trace_and_audit_middleware,
)
from hallu_defense.api.routes import router


def create_app() -> FastAPI:
    settings = get_settings()
    validate_endpoint_auth_coverage(router.routes)
    app = FastAPI(
        title="Hallu Defense Platform",
        version=__version__,
        description="Claim-centric and action-centric hallucination defense API.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allow_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        max_body_bytes=settings.max_request_body_bytes,
        body_timeout_seconds=settings.request_body_timeout_seconds,
        cors_allow_origins=settings.cors_allow_origins,
    )
    app.middleware("http")(trace_and_audit_middleware)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    app.include_router(router)
    return app


app = create_app()
