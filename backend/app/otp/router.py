"""Authenticator app, emailed code and backup code endpoints (Appendix B).  Owner: M2"""
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session as Db

from app.core.db import get_db
from app.core.errors import not_implemented
from app.models import AuthSession
from app.orchestrator.state import require_can_add_factor, require_recent_factor2, require_state
from app.otp.schemas import BackupCodesResponse, TotpEnrollResponse
from app.schemas.common import AuthResponse, CodeRequest, SessionState

router = APIRouter(tags=["M2 · Authenticator app, emailed and backup codes"])

LOGIN_STEP_2 = require_state(SessionState.FACTOR1_PASSED)


@router.post("/mfa/totp/enroll", response_model=TotpEnrollResponse)
def totp_enroll(db: Db = Depends(get_db), session: AuthSession = Depends(require_can_add_factor())) -> TotpEnrollResponse:
    """§4.3, §7.6: secret as link, then copyable text; QR code optional and last (client side)."""
    not_implemented("M2")


@router.post("/mfa/totp/confirm", response_model=AuthResponse)
def totp_confirm(
    body: CodeRequest, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(require_can_add_factor()),
) -> AuthResponse:
    """§4.3: the first correct code completes set-up."""
    not_implemented("M2")


@router.post("/mfa/totp/verify", response_model=AuthResponse)
def totp_verify(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """Fig. 5, step 2 with the app code."""
    not_implemented("M2")


@router.post("/mfa/totp/lost", response_model=AuthResponse)
def totp_lost(
    db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.AUTHENTICATED, SessionState.RESTRICTED)),
) -> AuthResponse:
    """§5.4: stops working at once; deleted after 24 hours unless cancelled (M5 hold)."""
    not_implemented("M2")


@router.delete("/mfa/totp", response_model=AuthResponse)
def totp_remove(db: Db = Depends(get_db), session: AuthSession = Depends(require_recent_factor2())) -> AuthResponse:
    """FR3, SR-9."""
    not_implemented("M2")


@router.post("/mfa/email/send", response_model=AuthResponse, status_code=status.HTTP_202_ACCEPTED)
def email_send(db: Db = Depends(get_db), session: AuthSession = Depends(LOGIN_STEP_2)) -> AuthResponse:
    """§5.4 weak route: only when the user has no strong factor and no backup code."""
    not_implemented("M2")


@router.post("/mfa/email/verify", response_model=AuthResponse)
def email_verify(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """§5.4: leads only to Restricted (M5's enter_restricted), never to Authenticated."""
    not_implemented("M2")


@router.post("/mfa/backup/generate", response_model=BackupCodesResponse)
def backup_generate(db: Db = Depends(get_db), session: AuthSession = Depends(require_recent_factor2())) -> BackupCodesResponse:
    """FR4: shown once."""
    not_implemented("M2")


@router.post("/mfa/backup/verify", response_model=AuthResponse)
def backup_verify(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """FR5: password + backup code is a full two-factor login."""
    not_implemented("M2")
