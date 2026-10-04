"""Authenticator app, emailed code and backup code endpoints (Appendix B).  Owner: M2"""
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session as Db

from app.core.db import get_db, utc_now
from app.core.errors import AppError
from app.core.policy import EMAIL_CODE_DIGITS, EMAIL_CODE_TTL_MINUTES, LOST_FACTOR_DELETE_HOURS
from app.models import AuthSession, PendingChange, SecondFactor, User
from app.orchestrator.audit import audit
from app.orchestrator.holds import start_hold
from app.orchestrator.lockout import check_lockout, record_failure, record_success
from app.orchestrator.state import (
    complete_factor2,
    enter_restricted,
    require_can_add_factor,
    require_recent_factor2,
    require_state,
)
from app.otp import backup_codes, totp
from app.otp.email_codes import EmailPurpose, issue_email_code, verify_email_code
from app.otp.schemas import BackupCodesResponse, TotpEnrollResponse
from app.schemas.common import AuthResponse, CodeRequest, NextStep, SessionState

router = APIRouter(tags=["M2 · Authenticator app, emailed and backup codes"])

LOGIN_STEP_2 = require_state(SessionState.FACTOR1_PASSED)
DELETE_LOST_FACTOR = "delete_lost_factor"


def _user(db: Db, session: AuthSession) -> User:
    return db.get(User, session.user_id)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _not_accepted(tries_left: int) -> AppError:
    """§5.3: the same words for every wrong code, with the tries left (SR-8)."""
    if tries_left <= 0:
        tries = "You have no tries left for now."
    elif tries_left == 1:
        tries = "One try left."
    else:
        tries = f"{tries_left} tries left."
    return AppError(401, "not_accepted", f"Not accepted. {tries}", tries_left=max(tries_left, 0))


def _check_login_code(db: Db, request: Request, user: User, event: str, is_correct) -> None:
    """Fig. 5: lockout check first, then the code; count a failure or reset the count."""
    ip = _ip(request)
    check_lockout(db, user.id, ip)
    if not is_correct():
        audit(db, event, "failure", user_id=user.id, ip=ip)
        raise _not_accepted(record_failure(db, user.id, ip))
    record_success(db, user.id)
    audit(db, event, "success", user_id=user.id, ip=ip)


def _has_strong_factor(db: Db, user: User) -> bool:
    """A working app or passkey: not reported lost, and an app only once confirmed."""
    factors = db.scalars(
        select(SecondFactor).where(SecondFactor.user_id == user.id, SecondFactor.suspended_at.is_(None))
    )
    return any(f.type != totp.APP or f.confirmed_at is not None for f in factors)


def _require_email_route(db: Db, user: User) -> None:
    """§5.4: the weak route is only for a user with no strong factor, no backup code and a confirmed address."""
    if _has_strong_factor(db, user) or backup_codes.remaining(db, user) > 0 or user.email_confirmed_at is None:
        raise AppError(
            403, "email_route_unavailable",
            "An emailed code cannot be used for this account. Use your authenticator app, your passkey or a backup code.",
            state=SessionState.FACTOR1_PASSED, next=NextStep.LOGIN_STEP2,
        )


# ---------- Authenticator app ----------


@router.post("/mfa/totp/enroll", response_model=TotpEnrollResponse)
def totp_enroll(
    request: Request, db: Db = Depends(get_db), session: AuthSession = Depends(require_can_add_factor())
) -> TotpEnrollResponse:
    """§4.3, §7.6: secret as link, then copyable text; QR code optional and last (client side)."""
    user = _user(db, session)
    enrolment = totp.start_enrolment(db, user)
    audit(db, "setup.app.start", "success", user_id=user.id, ip=_ip(request))
    return TotpEnrollResponse(
        state=SessionState(session.state),
        next=NextStep.SETUP,
        message="Add Cryptix to your authenticator app, then enter the 6-digit code the app shows.",
        otpauth_uri=enrolment.otpauth_uri,
        secret_grouped=enrolment.secret_grouped,
    )


@router.post("/mfa/totp/confirm", response_model=AuthResponse)
def totp_confirm(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(require_can_add_factor()),
) -> AuthResponse:
    """§4.3: the first correct code completes set-up."""
    user = _user(db, session)
    if not totp.confirm_enrolment(db, user, body.code):
        audit(db, "setup.app", "failure", user_id=user.id, ip=_ip(request))
        raise AppError(
            400, "not_accepted",
            "Not accepted. Check that the time on your phone is correct, then enter the newest code from the app.",
        )
    audit(db, "setup.app", "success", user_id=user.id, ip=_ip(request))
    # Fig. 4: one correct code proves the device, so the session becomes Authenticated with a new ID.
    result = complete_factor2(db, response, session, "app")
    return result.model_copy(update={
        "next": NextStep.BACKUP_CODES,
        "message": "Your authenticator app is set up. Next, save your backup codes.",
    })


@router.post("/mfa/totp/verify", response_model=AuthResponse)
def totp_verify(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """Fig. 5, step 2 with the app code."""
    user = _user(db, session)
    _check_login_code(db, request, user, "login.factor2.app", lambda: totp.verify_code(db, user, body.code))
    return complete_factor2(db, response, session, "app")


@router.post("/mfa/totp/lost", response_model=AuthResponse)
def totp_lost(
    request: Request, db: Db = Depends(get_db),
    session: AuthSession = Depends(require_state(SessionState.AUTHENTICATED, SessionState.RESTRICTED)),
) -> AuthResponse:
    """§5.4: stops working at once; deleted after 24 hours unless cancelled (M5 hold)."""
    user = _user(db, session)
    factor = totp.active_app(db, user)
    if factor is None:
        raise AppError(404, "not_found", "No authenticator app is set up, so there is nothing to report lost.")
    factor.suspended_at = utc_now()
    db.commit()
    start_hold(db, user, DELETE_LOST_FACTOR, factor.id)
    audit(db, "factor.app.lost", "success", user_id=user.id, ip=_ip(request))
    return AuthResponse(
        state=SessionState(session.state),
        next=NextStep.MANAGE_FACTORS,
        message=(
            "Your authenticator app no longer works for signing in. It will be removed in "
            f"{LOST_FACTOR_DELETE_HOURS} hours. If this was a mistake, use the cancel link we emailed you."
        ),
    )


@router.delete("/mfa/totp", response_model=AuthResponse)
def totp_remove(
    request: Request, db: Db = Depends(get_db), session: AuthSession = Depends(require_recent_factor2())
) -> AuthResponse:
    """FR3, SR-9."""
    user = _user(db, session)
    factors = db.scalars(select(SecondFactor).where(SecondFactor.user_id == user.id, SecondFactor.type == totp.APP)).all()
    if not factors:
        raise AppError(404, "not_found", "No authenticator app is set up, so there is nothing to remove.")
    ids = [f.id for f in factors]
    # A pending "delete when lost" for this app has nothing left to do: close it so the row can go.
    db.execute(
        update(PendingChange)
        .where(PendingChange.second_factor_id.in_(ids), PendingChange.completed_at.is_(None))
        .values(completed_at=utc_now())
    )
    db.execute(update(PendingChange).where(PendingChange.second_factor_id.in_(ids)).values(second_factor_id=None))
    for factor in factors:
        db.delete(factor)
    db.commit()
    audit(db, "factor.app.removed", "success", user_id=user.id, ip=_ip(request))
    return AuthResponse(
        state=SessionState(session.state),
        next=NextStep.MANAGE_FACTORS,
        message="Your authenticator app has been removed. Its codes no longer work.",
    )


# ---------- Emailed code (weak route) ----------


@router.post("/mfa/email/send", response_model=AuthResponse, status_code=status.HTTP_202_ACCEPTED)
def email_send(
    request: Request, db: Db = Depends(get_db), session: AuthSession = Depends(LOGIN_STEP_2)
) -> AuthResponse:
    """§5.4 weak route: only when the user has no strong factor and no backup code."""
    user = _user(db, session)
    _require_email_route(db, user)
    issue_email_code(db, user, EmailPurpose.LOGIN)
    audit(db, "login.email_code.sent", "success", user_id=user.id, ip=_ip(request))
    return AuthResponse(
        state=SessionState.FACTOR1_PASSED,
        next=NextStep.LOGIN_STEP2,
        message=(
            f"We emailed a {EMAIL_CODE_DIGITS}-digit code to your confirmed address. It works for {EMAIL_CODE_TTL_MINUTES} minutes. "
            "Enter it to continue."
        ),
    )


@router.post("/mfa/email/verify", response_model=AuthResponse)
def email_verify(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """§5.4: leads only to Restricted (M5's enter_restricted), never to Authenticated."""
    user = _user(db, session)
    _require_email_route(db, user)
    _check_login_code(
        db, request, user, "login.factor2.email",
        lambda: verify_email_code(db, user, EmailPurpose.LOGIN, body.code),
    )
    return enter_restricted(db, response, session)


# ---------- Backup codes ----------


@router.post("/mfa/backup/generate", response_model=BackupCodesResponse)
def backup_generate(
    request: Request, db: Db = Depends(get_db), session: AuthSession = Depends(require_recent_factor2())
) -> BackupCodesResponse:
    """FR4: shown once."""
    user = _user(db, session)
    codes = backup_codes.generate(db, user)
    audit(db, "setup.backup_codes", "success", user_id=user.id, ip=_ip(request))
    return BackupCodesResponse(
        state=SessionState(session.state),
        next=NextStep.BACKUP_CODES,
        message=(
            f"Here are your {len(codes)} backup codes. Each one works once. They will not be shown again, "
            "so save them somewhere safe now. Any older backup codes no longer work."
        ),
        codes=codes,
    )


@router.post("/mfa/backup/verify", response_model=AuthResponse)
def backup_verify(
    body: CodeRequest, request: Request, response: Response, db: Db = Depends(get_db),
    session: AuthSession = Depends(LOGIN_STEP_2),
) -> AuthResponse:
    """FR5: password + backup code is a full two-factor login."""
    user = _user(db, session)
    _check_login_code(db, request, user, "login.factor2.backup_code", lambda: backup_codes.verify(db, user, body.code))
    result = complete_factor2(db, response, session, "backup_code")
    left = backup_codes.remaining(db, user)
    if left == 0:
        note = "That was your last backup code. Create new ones on Manage factors now."
    elif left == 1:
        note = "You have 1 backup code left. Create new ones on Manage factors soon."
    else:
        note = f"You have {left} backup codes left."
    return result.model_copy(update={"message": f"{result.message} {note}"})
