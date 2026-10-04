"""Passkey ceremonies with py_webauthn (§4.3, §6.3 C4, §8.3, S3).  Owner: M3

Challenges come from M5's issue_challenge()/consume_challenge(), so they are
bound to this session and purpose and used once.
"""
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import AuthSession, SecondFactor, User


def registration_options(db: Db, session: AuthSession, user: User) -> dict:
    """PublicKeyCredentialCreationOptions as JSON. Device PIN is enough; no fingerprint required (§7.6)."""
    not_implemented("M3")


def verify_registration(db: Db, session: AuthSession, user: User, credential: dict, label: str | None) -> SecondFactor:
    """Check origin, challenge (consumed first) and attestation; store the public key only."""
    not_implemented("M3")


def authentication_options(db: Db, session: AuthSession, user: User) -> dict:
    """PublicKeyCredentialRequestOptions for the user's non-suspended passkeys."""
    not_implemented("M3")


def verify_authentication(db: Db, session: AuthSession, user: User, credential: dict) -> bool:
    """Consume the challenge, then verify signature, origin and sign count."""
    not_implemented("M3")
