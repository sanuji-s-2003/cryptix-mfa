"""Backup codes: ten 20-digit single-use codes (§4.3, FR4, §7.6).  Owner: M2"""
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import User


def generate(db: Db, user: User) -> list[str]:
    """Replace any old set. Store only Argon2id hashes; return the codes once, in groups of four digits."""
    not_implemented("M2")


def verify(db: Db, user: User, code: str) -> bool:
    """Accept an unused code once and mark it used."""
    not_implemented("M2")


def remaining(db: Db, user: User) -> int:
    """How many unused codes the user has left (FR4)."""
    not_implemented("M2")
