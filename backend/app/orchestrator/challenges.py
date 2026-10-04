"""Single-use challenges bound to one session and one purpose (D5, S1, §6.2-6.5).  Owner: M5

The same stored challenge defeats replay (single use), cut-and-paste (one
session) and interleaving (one purpose); see Figure 7.
"""
from enum import Enum

from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import AuthSession


class ChallengePurpose(str, Enum):
    LOGIN = "login"
    SETUP = "setup"
    RECOVERY = "recovery"


def issue_challenge(db: Db, session: AuthSession, purpose: ChallengePurpose) -> bytes:
    """Store a fresh random challenge on the session with its purpose and a 2-minute expiry."""
    not_implemented("M5")


def consume_challenge(
    db: Db, session: AuthSession, purpose: ChallengePurpose, expected: bytes | None = None
) -> bool:
    """Atomically clear the session's challenge if it exists, has this purpose, has not expired
    and (when `expected` is given, as for passkeys) equals `expected`.

    Call this BEFORE checking the proof (§6.2). Returns False if nothing was consumed.
    Two simultaneous calls: exactly one returns True (§6.5).
    """
    not_implemented("M5")
