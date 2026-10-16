"""Global exception handlers: every error is returned as
``{"error": {"code": ..., "message": ..., "details": ...}}``."""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, IntegrityError, NoResultFound, OperationalError
from sqlalchemy.orm.exc import StaleDataError
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("consentledger.api")

HTTP_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "too_many_requests",
    500: "internal_error",
    503: "service_unavailable",
}


class AppError(Exception):
    def __init__(
        self,
        status: int,
        message: str,
        code: str | None = None,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ):
        self.status, self.message, self.details, self.headers = status, message, details, headers
        self.code = code or HTTP_CODES.get(status, "error")
        super().__init__(message)


def error_body(code: str, message: str, details: Any = None) -> dict:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return body


def _db_error(exc: DBAPIError) -> tuple[int, str, str]:
    """Map PostgreSQL errors (SQLSTATE) to HTTP responses with a clean message."""
    orig = getattr(exc, "orig", None)
    sqlstate = getattr(orig, "sqlstate", None) or ""
    diag = getattr(orig, "diag", None)
    primary = (getattr(diag, "message_primary", None) or str(orig or exc)).strip()

    if sqlstate == "42501":  # insufficient_privilege, incl. RLS violations
        if "row-level security" in primary:
            primary = "You are not allowed to perform this action on that record"
        return 403, "forbidden", primary
    if sqlstate == "P0002":  # no_data_found
        return 404, "not_found", primary
    if sqlstate == "P0001":  # RAISE EXCEPTION in a procedure: business rule
        return 400, "rule_violation", primary
    if sqlstate == "23505":
        return 409, "conflict", "A record with these values already exists"
    if sqlstate == "23503":
        return 409, "conflict", "The record is referenced by, or refers to, another record"
    if sqlstate == "23514":
        return 422, "constraint_violation", f"Value rejected by a database rule: {primary}"
    if sqlstate in ("22P02", "22007", "22008", "22003"):
        return 422, "invalid_value", primary
    if sqlstate in ("40001", "40P01"):  # serialization failure, deadlock
        return 409, "conflict", "The record was changed at the same time; please try again"
    if sqlstate == "57014":  # statement timeout / cancelled
        return 503, "service_unavailable", "The database took too long to answer; please try again"
    if isinstance(exc, OperationalError) and not sqlstate:
        return 503, "service_unavailable", "The database is unavailable; please try again shortly"
    return 500, "database_error", "A database error occurred"


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            error_body(exc.code, exc.message, exc.details),
            status_code=exc.status,
            headers=exc.headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        message = (
            exc.detail if isinstance(exc.detail, str) else HTTP_CODES.get(exc.status_code, "error")
        )
        details = None if isinstance(exc.detail, str) else exc.detail
        return JSONResponse(
            error_body(HTTP_CODES.get(exc.status_code, "error"), message, details),
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(p) for p in err["loc"] if p not in ("body", "query", "path")),
                "message": err["msg"],
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            error_body("validation_error", "Some fields are invalid", details), status_code=422
        )

    @app.exception_handler(NoResultFound)
    async def _not_found(_: Request, __: NoResultFound) -> JSONResponse:
        return JSONResponse(error_body("not_found", "Record not found"), status_code=404)

    @app.exception_handler(StaleDataError)
    async def _stale(_: Request, __: StaleDataError) -> JSONResponse:
        # An UPDATE matched no row: under RLS that means the row is not writable
        return JSONResponse(
            error_body("forbidden", "You are not allowed to perform this action on that record"),
            status_code=403,
        )

    @app.exception_handler(IntegrityError)
    @app.exception_handler(DBAPIError)
    async def _db(_: Request, exc: DBAPIError) -> JSONResponse:
        status, code, message = _db_error(exc)
        if status >= 500:
            log.exception("Database error", exc_info=exc)
        return JSONResponse(error_body(code, message), status_code=status)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled error", exc_info=exc)
        return JSONResponse(
            error_body("internal_error", "Something went wrong on our side"), status_code=500
        )


__all__ = ["AppError", "HTTPException", "install_exception_handlers"]
