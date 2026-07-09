from __future__ import annotations

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware

from hallu_defense import __version__
from hallu_defense.api.dependencies import get_settings
from hallu_defense.api.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from hallu_defense.api.middleware import trace_and_audit_middleware
from hallu_defense.api.routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Hallu Defense Platform",
        version=__version__,
        description="Claim-centric and action-centric hallucination defense API.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(get_settings().cors_allow_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.middleware("http")(trace_and_audit_middleware)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    app.include_router(router)
    return app


app = create_app()
