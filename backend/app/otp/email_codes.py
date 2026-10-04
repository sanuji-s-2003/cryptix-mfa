"""Emailed one-time codes, each bound to one purpose (§1.6, §5.4, S2, SR-3).  Owner: M2"""
from enum import Enum

from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import User


class EmailPurpose(str, Enum):
    CONFIRM_EMAIL = "confirm_email"  # M1, registration
    LOGIN = "login"  # M2, weak route to Restricted
    RECOVERY = "recovery"  # M5, forgotten password


def issue_email_code(db: Db, user: User, purpose: EmailPurpose) -> None:
    """Generate an EMAIL_CODE_DIGITS code, store only its hash with purpose and expiry, email it."""
    not_implemented("M2")


def verify_email_code(db: Db, user: User, purpose: EmailPurpose, code: str) -> bool:
    """Accept once: mark used in the same database operation that checks it was unused (§6.2).
    A code issued for another purpose is refused (S2)."""
    not_implemented("M2")
