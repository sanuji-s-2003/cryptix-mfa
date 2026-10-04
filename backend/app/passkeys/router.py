"""Passkey and remembered-browser endpoints (Appendix B).  Owner: M3"""
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as Db

from app.core.db import get_db
from app.core.errors import not_implemented
from app.models import AuthSession
from app.orchestrator.state import require_can_add_factor, require_recent_factor2, require_state
from app.passkeys.schemas import CredentialListResponse, PasskeyOptionsResponse, PasskeyVerifyRequest
from app.schemas.common import AuthResponse, SessionState

router = APIRouter(tags=["M3 · Passkeys and remembered browser"])

LOGIN_STEP_2 = require_state(SessionState.FACTOR1_PASSED)


@router.post("/webauthn/register/options", response_model=PasskeyOptionsResponse)
def register_options(db: Db = Depends(get_db), session: AuthSession = Depends(require_can_add_factor())) -> PasskeyOptionsResponse:
    not_implemented("M3")


@router.post("/webauthn/register/verify", response_model=AuthResponse)
def register_verify(
    body: PasskeyVerifyRequest, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(require_can_add_factor()),
) -> AuthResponse:
    not_implemented("M3")


@router.post("/webauthn/login/options", response_model=PasskeyOptionsResponse)
def login_options(db: Db = Depends(get_db), session: AuthSession = Depends(LOGIN_STEP_2)) -> PasskeyOptionsResponse:
    not_implemented("M3")


@router.post("/webauthn/login/verify", response_model=AuthResponse)
def login_verify(
    body: PasskeyVerifyRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """Fig. 5, step 2 with a passkey."""
    not_implemented("M3")


@router.get("/webauthn/credentials", response_model=CredentialListResponse)
def list_credentials(
    db: Db = Depends(get_db), session: AuthSession = Depends(require_state(SessionState.AUTHENTICATED))
) -> CredentialListResponse:
    not_implemented("M3")


@router.post("/webauthn/credentials/{credential_id}/lost", response_model=AuthResponse)
def report_lost(
    credential_id: int, db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.AUTHENTICATED, SessionState.RESTRICTED)),
) -> AuthResponse:
    """§5.4: stops working at once; deleted after 24 hours unless cancelled (M5 hold)."""
    not_implemented("M3")


@router.delete("/webauthn/credentials/{credential_id}", response_model=AuthResponse)
def remove_credential(
    credential_id: int, db: Db = Depends(get_db), session: AuthSession = Depends(require_recent_factor2())
) -> AuthResponse:
    not_implemented("M3")


@router.post("/device/remember", response_model=AuthResponse)
def device_remember(
    response: Response, db: Db = Depends(get_db), session: AuthSession = Depends(require_recent_factor2())
) -> AuthResponse:
    """§4.7: remembering a browser needs the second factor proven within 5 minutes."""
    not_implemented("M3")


@router.post("/device/verify", response_model=AuthResponse)
def device_verify(
    request: Request, response: Response, db: Db = Depends(get_db), session: AuthSession = Depends(LOGIN_STEP_2)
) -> AuthResponse:
    """Fig. 3: valid remembered-browser token after Factor 1 -> Authenticated (M5's complete_remembered_browser)."""
    not_implemented("M3")


@router.delete("/device", response_model=AuthResponse)
def device_forget(
    request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.AUTHENTICATED)),
) -> AuthResponse:
    not_implemented("M3")
