"""Helpers shared by the three kinds of typed code.  Owner: M2"""
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Argon2id (SR-5). Backup codes carry 66 bits and emailed codes expire in minutes, so the
# OWASP minimum parameters are enough and keep checking ten backup codes quick.
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


def normalize(code: str) -> str:
    """Spaces and hyphens are allowed in every code field (§7.6)."""
    return "".join(ch for ch in code if ch not in " -\t")


def is_digits(code: str, length: int) -> bool:
    return len(code) == length and code.isascii() and code.isdigit()


def random_digits(length: int) -> str:
    return f"{secrets.randbelow(10**length):0{length}d}"


def group(value: str, size: int) -> str:
    """Turn "12345678" into "1234 5678": easier to copy, and read in short groups by a screen reader (§7.6)."""
    return " ".join(value[i : i + size] for i in range(0, len(value), size))


def hash_code(code: str) -> str:
    return _hasher.hash(code)


def check_code(stored_hash: str, code: str) -> bool:
    try:
        return _hasher.verify(stored_hash, code)
    except (VerificationError, InvalidHashError):
        return False
