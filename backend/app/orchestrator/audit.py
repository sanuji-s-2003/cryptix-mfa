"""Append-only audit log (FR8, §8.5, D10).  Owner: M5

Every member calls audit() for every login, set-up, failure, lockout and
recovery event in their slice. Never write a secret into `event`.
"""
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented


def audit(db: Db, event: str, outcome: str, *, user_id: int | None = None, ip: str | None = None) -> None:
    """Add one AuditLog row. `event` like "login.factor1", `outcome` "success" or "failure"."""
    not_implemented("M5")
