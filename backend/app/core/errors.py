"""The one error shape every endpoint uses.  [SHARED contract file]

Raise AppError anywhere. Never return a bare HTTPException with a technical
message: every error must be a full sentence that can be read aloud (AR-5), and
wrong answers must all look the same (SR-8).
"""
from typing import NoReturn

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.schemas.common import ErrorResponse, NextStep, SessionState


class AppError(Exception):
    def __init__(
        self,
        status_code: int,
        error: str,
        message: str,
        *,
        state: SessionState | None = None,
        next: NextStep | None = None,
        tries_left: int | None = None,
        retry_after_seconds: int | None = None,
        fields: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = ErrorResponse(
            error=error,
            message=message,
            state=state,
            next=next,
            tries_left=tries_left,
            retry_after_seconds=retry_after_seconds,
            fields=fields,
        )


def not_implemented(owner: str) -> NoReturn:
    """Placeholder for code its owner has not built yet. Delete the call when you build it."""
    raise AppError(501, "not_implemented", f"This step has not been built yet. Owner: {owner}.")


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(exc.body.model_dump(mode="json", exclude_none=True), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _invalid_input(_: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted({str(e["loc"][-1]) for e in exc.errors() if e.get("loc")})
        body = ErrorResponse(
            error="invalid_input",
            message="Some of the information is missing or in the wrong format. Check each field and try again.",
            fields=fields or None,
        )
        return JSONResponse(body.model_dump(mode="json", exclude_none=True), status_code=422)
