"""Session records (SR-7, §4.7, §6.6, D7).  Owner: M1

The browser holds a long random session ID in an httpOnly, Secure,
SameSite=Strict cookie; the server stores only its SHA-256 hash. This module
creates, loads, rotates and deletes records. Which state a session is in is
decided by M5 (orchestrator/state.py).
"""
from fastapi import Request, Response
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import AuthSession
from app.schemas.common import SessionState

SESSION_COOKIE = "cryptix_session"


def create_session(db: Db, response: Response, user_id: int, state: SessionState) -> AuthSession:
    """New random ID, new CSRF token, expires_at = now + SESSION_ABSOLUTE_HOURS; set the cookie."""
    not_implemented("M1")


def load_session(db: Db, request: Request) -> AuthSession | None:
    """The session for the request's cookie, or None if missing, unknown, idle longer than
    SESSION_IDLE_MINUTES or past expires_at. Updates last_seen_at."""
    not_implemented("M1")


def rotate_session_id(db: Db, response: Response, session: AuthSession) -> AuthSession:
    """Give the same session a new random ID after every authentication step (§4.7)."""
    not_implemented("M1")


def end_session(db: Db, response: Response, session: AuthSession) -> None:
    """Delete the record on the server at once and clear the cookie (logout)."""
    not_implemented("M1")


def end_all_sessions(db: Db, user_id: int) -> None:
    """Delete every session of this user (password reset, FR6)."""
    not_implemented("M1")
