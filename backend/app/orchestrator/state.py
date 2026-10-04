"""Login state machine (Figure 3, §4.7, §6.7, D6).  Owner: M5

Every request is checked against the state the server holds for its session.
The client never decides on its own that a user is signed in (SR-2).
Other members use the dependencies below in their routers; they never read or
change AuthSession.state themselves.
"""
from collections.abc import Callable

from fastapi import Depends, Request, Response
from sqlalchemy.orm import Session as Db

from app.core.db import get_db
from app.core.errors import not_implemented
from app.models import AuthSession, User
from app.schemas.common import AuthResponse, SessionState


def current_session(request: Request, db: Db = Depends(get_db)) -> AuthSession | None:
    """The live session for this request, or None. Uses M1's load_session()."""
    not_implemented("M5")


def require_state(*allowed: SessionState) -> Callable[..., AuthSession]:
    """Dependency: refuse the request unless its session is in one of `allowed` (SR-2).

    Usage:  session: AuthSession = Depends(require_state(SessionState.FACTOR1_PASSED))
    """

    def dependency(request: Request, db: Db = Depends(get_db)) -> AuthSession:
        not_implemented("M5")

    return dependency


def require_recent_factor2() -> Callable[..., AuthSession]:
    """Dependency: Authenticated AND the second factor proven within REAUTH_WINDOW_MINUTES (SR-9).

    A remembered browser never satisfies this check (§4.7).
    """

    def dependency(request: Request, db: Db = Depends(get_db)) -> AuthSession:
        not_implemented("M5")

    return dependency


def require_can_add_factor() -> Callable[..., AuthSession]:
    """Dependency for every set-up endpoint. Allowed only for:
    - a new account's first set-up (Restricted, no confirmed factor yet; Fig. 4),
    - Authenticated with the second factor proven recently (SR-9),
    - Restricted through the email route after the 24-hour waiting period (SR-10).
    """

    def dependency(request: Request, db: Db = Depends(get_db)) -> AuthSession:
        not_implemented("M5")

    return dependency


def complete_factor1(db: Db, request: Request, response: Response, user: User) -> AuthResponse:
    """Password/PIN accepted: new session (or rotated ID) in FACTOR1_PASSED, next = login_step2."""
    not_implemented("M5")


def complete_factor2(db: Db, response: Response, session: AuthSession, method: str) -> AuthResponse:
    """Passkey, app code or backup code accepted: AUTHENTICATED, factor2_at = now, new session ID."""
    not_implemented("M5")


def complete_remembered_browser(db: Db, response: Response, session: AuthSession) -> AuthResponse:
    """Valid remembered-browser token after Factor 1: AUTHENTICATED, but factor2_at is NOT set (§4.7)."""
    not_implemented("M5")


def enter_restricted(db: Db, response: Response, session: AuthSession) -> AuthResponse:
    """Emailed code accepted with no strong factor available: RESTRICTED, new session ID (§5.4)."""
    not_implemented("M5")
