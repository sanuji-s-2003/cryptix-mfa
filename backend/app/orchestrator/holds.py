"""24-hour waiting periods with a cancel link (§5.4, SR-10).  Owner: M5

Used for the email route (Restricted may add a factor only after the wait) and
for deleting a factor reported lost.
"""
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import User


def start_hold(db: Db, user: User, kind: str, second_factor_id: int | None = None) -> None:
    """Create a PendingChange and email the confirmed address a cancel link (M2's send_email)."""
    not_implemented("M5")


def hold_is_over(db: Db, user: User, kind: str) -> bool:
    """True if a hold of this kind exists, was not cancelled, and its 24 hours have passed."""
    not_implemented("M5")


def cancel_hold(db: Db, token: str) -> bool:
    """Cancel the hold whose cancel token matches. Returns False for an unknown or used token."""
    not_implemented("M5")
