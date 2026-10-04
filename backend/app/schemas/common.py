"""Shapes every endpoint shares (Appendix B).  [SHARED contract file]

"Every response tells the client the current state, the next step, and a
sentence to be read aloud." The client (M4) maps `next` to a page; see
NEXT_STEP_PAGES in frontend/js/api.js.
"""
from enum import Enum

from pydantic import BaseModel, Field


class SessionState(str, Enum):
    """The states of Figure 3. Held only on the server (D6)."""

    ANONYMOUS = "anonymous"
    FACTOR1_PASSED = "factor1_passed"
    RESTRICTED = "restricted"
    AUTHENTICATED = "authenticated"
    LOCKED = "locked"
    LOCKED_UNTIL_RECOVERY = "locked_until_recovery"


class NextStep(str, Enum):
    """One value per screen in §7.8."""

    REGISTER = "register"
    CHOOSE_FACTOR = "choose_factor"
    SETUP = "setup"
    BACKUP_CODES = "backup_codes"
    LOGIN_STEP1 = "login_step1"
    LOGIN_STEP2 = "login_step2"
    SIGNED_IN = "signed_in"
    MANAGE_FACTORS = "manage_factors"
    RECOVERY = "recovery"


class AuthResponse(BaseModel):
    state: SessionState
    next: NextStep | None = None
    message: str = Field(description="Full sentence, shown on the page and announced (AR-4, AR-5)")


class ErrorResponse(BaseModel):
    error: str = Field(description="Machine-readable code, e.g. not_accepted, locked")
    message: str = Field(description="Full sentence: what happened and what to do next (AR-5)")
    state: SessionState | None = None
    next: NextStep | None = None
    tries_left: int | None = None
    retry_after_seconds: int | None = None
    fields: list[str] | None = Field(default=None, description="Form fields the message refers to")


class CodeRequest(BaseModel):
    """Any typed code. Spaces and hyphens are allowed and must be stripped before checking (§7.6)."""

    code: str = Field(min_length=1, max_length=64)
