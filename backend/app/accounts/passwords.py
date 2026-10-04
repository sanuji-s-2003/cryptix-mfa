"""Factor 1: password or PIN (§4.2, §6.1, §8.1, D2).  Owner: M1"""
from app.core.errors import not_implemented


def validate_new_secret(secret: str, kind: str) -> None:
    """Refuse a password shorter than PASSWORD_MIN_LENGTH, a PIN that is not at least
    PIN_MIN_DIGITS digits, or anything on the common-password list (§4.2).
    Raise AppError with a full sentence saying what to change (AR-5)."""
    not_implemented("M1")


def hash_secret(secret: str) -> str:
    """Salted Argon2id hash (RFC 9106) using argon2-cffi."""
    not_implemented("M1")


def verify_secret(stored_hash: str | None, secret: str) -> bool:
    """Check against the stored hash. If stored_hash is None (unknown username), still spend
    the same time on a dummy hash so timing does not reveal which usernames exist (SR-8)."""
    not_implemented("M1")
