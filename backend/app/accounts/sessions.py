"""Session records (SR-7, §4.7, §6.6, D7).  Owner: M1

The browser holds a long random session ID in an httpOnly, Secure,
SameSite=Strict cookie; the server stores only its SHA-256 hash. This module
creates, loads, rotates and deletes records. Which state a session is in is
decided by M5 (orchestrator/state.py).
"""
import hashlib
import secrets
from datetime import timedelta

from fastapi import Request, Response
from sqlalchemy import delete
from sqlalchemy.orm import Session as Db

from app.core.db import utc_now
from app.core.policy import SESSION_ABSOLUTE_HOURS, SESSION_IDLE_MINUTES
from app.models import AuthSession
from app.schemas.common import SessionState

SESSION_COOKIE = "cryptix_session"
SESSION_ID_BYTES = 32  # 256 bits of randomness


def _hash(raw_id: str) -> bytes:
    return hashlib.sha256(raw_id.encode()).digest()


def _set_cookie(response: Response, raw_id: str) -> None:
    # No max_age: the browser forgets the cookie when it closes; the server enforces both limits.
    response.set_cookie(SESSION_COOKIE, raw_id, httponly=True, secure=True, samesite="strict", path="/")


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, httponly=True, secure=True, samesite="strict", path="/")


def create_session(db: Db, response: Response, user_id: int, state: SessionState) -> AuthSession:
    """New random ID, new CSRF token, expires_at = now + SESSION_ABSOLUTE_HOURS; set the cookie."""
    raw_id = secrets.token_urlsafe(SESSION_ID_BYTES)
    now = utc_now()
    session = AuthSession(
        session_id_hash=_hash(raw_id),
        user_id=user_id,
        state=state.value,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=SESSION_ABSOLUTE_HOURS),
    )
    db.add(session)
    db.commit()
    _set_cookie(response, raw_id)
    return session


def load_session(db: Db, request: Request) -> AuthSession | None:
    """The session for the request's cookie, or None if missing, unknown, idle longer than
    SESSION_IDLE_MINUTES or past expires_at. Updates last_seen_at."""
    raw_id = request.cookies.get(SESSION_COOKIE)
    if not raw_id:
        return None
    session = db.get(AuthSession, _hash(raw_id))
    if session is None:
        return None
    now = utc_now()
    if now >= session.expires_at or now - session.last_seen_at > timedelta(minutes=SESSION_IDLE_MINUTES):
        db.delete(session)
        db.commit()
        return None
    session.last_seen_at = now
    db.commit()
    return session


def rotate_session_id(db: Db, response: Response, session: AuthSession) -> AuthSession:
    """Give the same session a new random ID after every authentication step (§4.7).

    The ID hash is the primary key, so the record is copied under the new hash and the old
    one deleted. Everything else, including created_at and expires_at, is kept: the 12-hour
    limit counts from the first step. Use the returned object from here on.
    """
    raw_id = secrets.token_urlsafe(SESSION_ID_BYTES)
    rotated = AuthSession(
        session_id_hash=_hash(raw_id),
        user_id=session.user_id,
        state=session.state,
        challenge=session.challenge,
        challenge_purpose=session.challenge_purpose,
        challenge_expires_at=session.challenge_expires_at,
        csrf_token=session.csrf_token,
        factor2_at=session.factor2_at,
        created_at=session.created_at,
        last_seen_at=utc_now(),
        expires_at=session.expires_at,
    )
    db.delete(session)
    db.flush()
    db.add(rotated)
    db.commit()
    _set_cookie(response, raw_id)
    return rotated


def end_session(db: Db, response: Response, session: AuthSession) -> None:
    """Delete the record on the server at once and clear the cookie (logout)."""
    db.delete(session)
    db.commit()
    clear_session_cookie(response)


def end_all_sessions(db: Db, user_id: int) -> None:
    """Delete every session of this user (password reset, FR6)."""
    db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
    db.commit()
