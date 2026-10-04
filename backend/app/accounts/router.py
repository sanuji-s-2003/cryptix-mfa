"""Accounts and Factor 1 endpoints (Appendix B).  Owner: M1"""
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session as Db

from app.accounts.schemas import LoginRequest, RegisterRequest
from app.core.db import get_db
from app.core.errors import not_implemented
from app.models import AuthSession
from app.orchestrator.state import require_state
from app.schemas.common import AuthResponse, CodeRequest, SessionState

router = APIRouter(tags=["M1 · Accounts and Factor 1"])


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, response: Response, db: Db = Depends(get_db)) -> AuthResponse:
    """FR1, Fig. 4: create the user, email a confirmation code, start a Restricted session."""
    not_implemented("M1")


@router.post("/email/verify", response_model=AuthResponse)
def verify_email(
    body: CodeRequest,
    db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.RESTRICTED, SessionState.AUTHENTICATED)),
) -> AuthResponse:
    """FR1: confirm the address with the emailed code (purpose confirm_email)."""
    not_implemented("M1")


@router.post("/email/resend", response_model=AuthResponse, status_code=status.HTTP_202_ACCEPTED)
def resend_email(
    db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.RESTRICTED, SessionState.AUTHENTICATED)),
) -> AuthResponse:
    """FR1: send a new confirmation code."""
    not_implemented("M1")


@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, request: Request, response: Response, db: Db = Depends(get_db)) -> AuthResponse:
    """Fig. 5, step 1: lockout check (M5) -> verify password/PIN -> complete_factor1 (M5)."""
    not_implemented("M1")


@router.post("/logout", response_model=AuthResponse)
def logout(request: Request, response: Response, db: Db = Depends(get_db)) -> AuthResponse:
    """SR-7: delete the session on the server at once."""
    not_implemented("M1")
