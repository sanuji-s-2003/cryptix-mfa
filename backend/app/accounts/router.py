"""Accounts and Factor 1 endpoints (Appendix B).  Owner: M1"""
import re

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as Db

from app.accounts.passwords import hash_secret, validate_new_secret, verify_secret
from app.accounts.schemas import LoginRequest, RegisterRequest
from app.accounts.sessions import clear_session_cookie, create_session, end_session, load_session
from app.core.crypto import encrypt_for_user, keyed_hash
from app.core.db import get_db, utc_now
from app.core.errors import AppError
from app.models import AuthSession, User
from app.orchestrator.audit import audit
from app.orchestrator.lockout import check_lockout, record_failure, record_success
from app.orchestrator.state import complete_factor1, require_state
from app.otp.email_codes import EMAIL_FIELD, EmailPurpose, issue_email_code, verify_email_code
from app.schemas.common import AuthResponse, CodeRequest, NextStep, SessionState

router = APIRouter(tags=["M1 · Accounts and Factor 1"])

SIGNED_IN_OR_RESTRICTED = require_state(SessionState.RESTRICTED, SessionState.AUTHENTICATED)

# Deliberately loose: one "@", something on each side, a dot in the domain. The emailed code is the real check.
_EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def normalize_email(email: str) -> str:
    """One spelling per address, so the keyed hash finds it however it was typed."""
    return email.strip().lower()


def _not_accepted(tries_left: int) -> AppError:
    """§5.3: the same words for every wrong password, PIN or code, with the tries left (SR-8)."""
    if tries_left <= 0:
        tries = "You have no tries left for now."
    elif tries_left == 1:
        tries = "One try left."
    else:
        tries = f"{tries_left} tries left."
    return AppError(401, "not_accepted", f"Not accepted. {tries}", tries_left=max(tries_left, 0))


def _send_confirmation(db: Db, user: User) -> bool:
    """Email a confirm_email code. False if the mail server refused, so the caller can say so."""
    try:
        issue_email_code(db, user, EmailPurpose.CONFIRM_EMAIL)
    except AppError as exc:
        if exc.body.error != "email_failed":
            raise
        return False
    return True


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, response: Response, db: Db = Depends(get_db)) -> AuthResponse:
    """FR1, Fig. 4: create the user, email a confirmation code, start a Restricted session."""
    ip = _ip(request)
    username = body.username
    email = normalize_email(body.email)
    if not _EMAIL_PATTERN.fullmatch(email):
        raise AppError(
            422, "invalid_input",
            "This email address does not look complete. Check it has an @ sign and a domain, such as name@example.com.",
            fields=["email"],
        )
    validate_new_secret(body.secret, body.secret_kind)

    taken = AppError(
        409, "username_taken", "This username is already in use. Choose a different username.", fields=["username"]
    )
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise taken
    email_hash = keyed_hash(email)
    if db.scalar(select(User.id).where(User.email_lookup_hash == email_hash)) is not None:
        raise AppError(
            409, "email_taken",
            "This email address is already used by another account. Sign in to that account, or use a different address.",
            fields=["email"],
        )

    user = User(
        username=username,
        password_hash=hash_secret(body.secret),
        secret_kind=body.secret_kind,
        email_lookup_hash=email_hash,
    )
    db.add(user)
    try:
        db.flush()  # assigns user.id, which the encryption is bound to (S4)
    except IntegrityError:
        db.rollback()
        raise taken
    user.email_encrypted = encrypt_for_user(user.id, EMAIL_FIELD, email.encode())
    db.commit()

    # A session this browser already had (another account, or one planted) ends here (SR-7).
    previous = load_session(db, request)
    if previous is not None:
        db.delete(previous)  # the new cookie below replaces the old one
        db.commit()
    create_session(db, response, user.id, SessionState.RESTRICTED)
    audit(db, "register", "success", user_id=user.id, ip=ip)

    if _send_confirmation(db, user):
        email_note = "We emailed you a code to confirm your address."
    else:
        email_note = "We could not send the email to confirm your address just now. You can ask for it again later."
    return AuthResponse(
        state=SessionState.RESTRICTED,
        next=NextStep.CHOOSE_FACTOR,
        message=f"Your account is created. {email_note} Now set up a second factor to finish.",
    )


@router.post("/email/verify", response_model=AuthResponse)
def verify_email(
    body: CodeRequest,
    request: Request,
    db: Db = Depends(get_db),
    session: AuthSession = Depends(SIGNED_IN_OR_RESTRICTED),
) -> AuthResponse:
    """FR1: confirm the address with the emailed code (purpose confirm_email)."""
    user = db.get(User, session.user_id)
    state = SessionState(session.state)
    if user.email_confirmed_at is not None:
        return AuthResponse(state=state, message="Your email address is already confirmed. There is nothing more to do.")

    ip = _ip(request)
    check_lockout(db, user.id, ip)
    if not verify_email_code(db, user, EmailPurpose.CONFIRM_EMAIL, body.code):
        audit(db, "email.confirm", "failure", user_id=user.id, ip=ip)
        raise _not_accepted(record_failure(db, user.id, ip))
    record_success(db, user.id)
    user.email_confirmed_at = utc_now()
    db.commit()
    audit(db, "email.confirm", "success", user_id=user.id, ip=ip)
    return AuthResponse(state=state, message="Your email address is confirmed.")


@router.post("/email/resend", response_model=AuthResponse, status_code=status.HTTP_202_ACCEPTED)
def resend_email(
    request: Request,
    db: Db = Depends(get_db),
    session: AuthSession = Depends(SIGNED_IN_OR_RESTRICTED),
) -> AuthResponse:
    """FR1: send a new confirmation code."""
    user = db.get(User, session.user_id)
    state = SessionState(session.state)
    if user.email_confirmed_at is not None:
        return AuthResponse(state=state, message="Your email address is already confirmed. There is nothing more to do.")
    if not _send_confirmation(db, user):
        raise AppError(503, "email_failed", "We could not send the email just now. Wait a few minutes and try again.")
    audit(db, "email.resend", "success", user_id=user.id, ip=_ip(request))
    return AuthResponse(
        state=state,
        message="We emailed you a new code. Any earlier code no longer works. Type the new code to confirm your address.",
    )


@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, request: Request, response: Response, db: Db = Depends(get_db)) -> AuthResponse:
    """Fig. 5, step 1: lockout check (M5) -> verify password/PIN -> complete_factor1 (M5)."""
    ip = _ip(request)
    user = db.scalar(select(User).where(User.username == body.username))
    user_id = user.id if user else None

    check_lockout(db, user_id, ip)
    # An unknown username still costs one Argon2 check, and gets the same answer (SR-8).
    if not verify_secret(user.password_hash if user else None, body.secret):
        audit(db, "login.factor1", "failure", user_id=user_id, ip=ip)
        raise _not_accepted(record_failure(db, user_id, ip))

    record_success(db, user.id)
    audit(db, "login.factor1", "success", user_id=user.id, ip=ip)
    return complete_factor1(db, request, response, user)


@router.post("/logout", response_model=AuthResponse)
def logout(request: Request, response: Response, db: Db = Depends(get_db)) -> AuthResponse:
    """SR-7: delete the session on the server at once."""
    session = load_session(db, request)
    if session is not None:
        user_id = session.user_id
        end_session(db, response, session)
        audit(db, "logout", "success", user_id=user_id, ip=_ip(request))
    else:
        clear_session_cookie(response)
    return AuthResponse(state=SessionState.ANONYMOUS, next=NextStep.LOGIN_STEP1, message="You are signed out.")
