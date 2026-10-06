"""Factor 1: password or PIN (§4.2, §6.1, §8.1, D2).  Owner: M1"""
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.errors import AppError
from app.core.policy import PASSWORD_MIN_LENGTH, PIN_MIN_DIGITS

# SecLists "10k most common" (Passwords/Common-Credentials/10k-most-common.txt), one per line.
COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")

# Argon2id with argon2-cffi's defaults, the RFC 9106 low-memory profile (64 MiB, 3 passes).
_hasher = PasswordHasher()
# Checked when the username is unknown, so that answer takes as long as a wrong password (SR-8).
_DUMMY_HASH = _hasher.hash("cryptix-dummy-secret-for-unknown-users")


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    lines = COMMON_PASSWORDS_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip())


def _refuse(message: str) -> None:
    raise AppError(422, "weak_secret", message, fields=["secret"])


def validate_new_secret(secret: str, kind: str) -> None:
    """Refuse a password shorter than PASSWORD_MIN_LENGTH, a PIN that is not at least
    PIN_MIN_DIGITS digits, or anything on the common-password list (§4.2).
    Raise AppError with a full sentence saying what to change (AR-5)."""
    if kind == "pin":
        if not (secret.isascii() and secret.isdigit()):
            _refuse("A PIN can contain only the digits 0 to 9. Type digits only, or choose a password instead.")
        if len(secret) < PIN_MIN_DIGITS:
            _refuse(f"Your PIN is too short. Choose a PIN of at least {PIN_MIN_DIGITS} digits.")
        if secret.lower() in _common_passwords():
            _refuse("This PIN is one of the most commonly used and is easy to guess. Choose a different PIN.")
    elif kind == "password":
        if len(secret) < PASSWORD_MIN_LENGTH:
            _refuse(f"Your password is too short. Choose a password of at least {PASSWORD_MIN_LENGTH} characters.")
        if secret.lower() in _common_passwords():
            _refuse("This password is one of the most commonly used and is easy to guess. Choose a different password.")
    else:
        _refuse("Choose whether you are setting a password or a PIN, then try again.")


def hash_secret(secret: str) -> str:
    """Salted Argon2id hash (RFC 9106) using argon2-cffi."""
    return _hasher.hash(secret)


def verify_secret(stored_hash: str | None, secret: str) -> bool:
    """Check against the stored hash. If stored_hash is None (unknown username), still spend
    the same time on a dummy hash so timing does not reveal which usernames exist (SR-8)."""
    try:
        if stored_hash is None:
            _hasher.verify(_DUMMY_HASH, secret)
            return False
        return _hasher.verify(stored_hash, secret)
    except (VerificationError, InvalidHashError):
        return False
