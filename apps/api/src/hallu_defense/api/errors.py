from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from hallu_defense.domain.models import ErrorResponse
from hallu_defense.services.trace import current_trace_id


def error_content(
    *,
    error: str,
    message: str,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return ErrorResponse(
        trace_id=current_trace_id(),
        error=error,
        message=message,
        details=details or {},
    ).model_dump(mode="json")


async def http_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, HTTPException):
        raise exc
    message = str(exc.detail) if exc.detail else "HTTP request failed."
    return JSONResponse(
        status_code=exc.status_code,
        content=error_content(
            error=f"http_{exc.status_code}",
            message=message,
        ),
        headers={"x-trace-id": current_trace_id()},
    )


async def validation_exception_handler(
    _request: Request,
    exc: Exception,
) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        raise exc
    return JSONResponse(
        status_code=422,
        content=error_content(
            error="validation_error",
            message="Request payload failed validation.",
            details={"errors": exc.errors()},
        ),
        headers={"x-trace-id": current_trace_id()},
    )


async def unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=error_content(
            error="internal_server_error",
            message="Unexpected server error.",
            details={"exception_type": type(exc).__name__},
        ),
        headers={"x-trace-id": current_trace_id()},
    )
