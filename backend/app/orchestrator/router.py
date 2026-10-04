"""Orchestration and recovery endpoints (Appendix B).  Owner: M5"""
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session as Db

from app.core.db import get_db
from app.core.errors import not_implemented
from app.models import AuthSession
from app.orchestrator.schemas import RecoveryStartRequest, RecoveryVerifyRequest, StatusResponse
from app.orchestrator.state import require_state
from app.schemas.common import AuthResponse, SessionState

router = APIRouter(tags=["M5 · Orchestration and recovery"])


@router.get("/auth/status", response_model=StatusResponse)
def auth_status(request: Request, db: Db = Depends(get_db)) -> StatusResponse:
    """The client calls this on every page load and never decides the state itself (D6)."""
    not_implemented("M5")


@router.post("/recovery/start", response_model=AuthResponse, status_code=status.HTTP_202_ACCEPTED)
def recovery_start(body: RecoveryStartRequest, request: Request, db: Db = Depends(get_db)) -> AuthResponse:
    """FR6: email a recovery code. Same answer whether or not the username exists (SR-8)."""
    not_implemented("M5")


@router.post("/recovery/verify", response_model=AuthResponse)
def recovery_verify(
    body: RecoveryVerifyRequest, request: Request, response: Response, db: Db = Depends(get_db)
) -> AuthResponse:
    """FR6: reset Factor 1 only, end every session; the second factor is still required next login."""
    not_implemented("M5")


@router.get("/mfa/cancel/{token}", response_model=AuthResponse)
def cancel_waiting_period(token: str, db: Db = Depends(get_db)) -> AuthResponse:
    """§5.4: the cancel link from the notification email stops a waiting period or deletion."""
    not_implemented("M5")


@router.post("/mfa/restricted/hold", response_model=AuthResponse)
def restricted_hold(
    request: Request,
    db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.RESTRICTED)),
) -> AuthResponse:
    """SR-10: start the 24-hour wait before a Restricted session may add a new factor."""
    not_implemented("M5")
