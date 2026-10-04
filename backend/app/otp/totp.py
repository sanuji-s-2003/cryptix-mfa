"""Authenticator-app codes (RFC 6238; §4.3, §6.2, §7.6).  Owner: M2"""
from dataclasses import dataclass

from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import User


@dataclass
class TotpEnrolment:
    otpauth_uri: str  # opens the authenticator app directly: offered first (§7.6)
    secret_grouped: str  # copyable text in groups of four, for copying and speech


def start_enrolment(db: Db, user: User) -> TotpEnrolment:
    """New random secret, stored encrypted (M1's encrypt_for_user), unconfirmed until one correct code."""
    not_implemented("M2")


def confirm_enrolment(db: Db, user: User, code: str) -> bool:
    """§4.3: set-up is complete only when one correct code comes back."""
    not_implemented("M2")


def verify_code(db: Db, user: User, code: str) -> bool:
    """±TOTP_VALID_WINDOW steps; refuse a code from last_code_step or earlier (replay, §6.2)."""
    not_implemented("M2")
