"""Wrong-attempt limits per account and per network address (§5.3, SR-6).  Owner: M5"""
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented


def check_lockout(db: Db, user_id: int | None, ip: str) -> None:
    """Raise AppError (same wording for every case, SR-8) if the account or address is locked.

    Call before checking any password, PIN or code.
    """
    not_implemented("M5")


def record_failure(db: Db, user_id: int | None, ip: str) -> int:
    """Count a wrong attempt; lock when the limits in core/policy.py are reached.

    Returns the tries left before the next lock, for "Not accepted. Two tries left."
    """
    not_implemented("M5")


def record_success(db: Db, user_id: int) -> None:
    """Reset the consecutive count after a correct answer."""
    not_implemented("M5")
