"""Encryption and keyed hashing for stored values (§8.2, S4, D10).  Owner: M1

Used by M1 (email address) and M2 (authenticator-app secret). Keys come from
settings.data_key and settings.hmac_key, never from the database (A5).
Use the `cryptography` library only; no hand-written cryptography (§3.1).
"""
from app.core.errors import not_implemented


def encrypt_for_user(user_id: int, field: str, plaintext: bytes) -> bytes:
    """AES-256-GCM with a fresh nonce. Associated data = f"{field}:{user_id}", so a value
    copied into another user's record fails to decrypt (S4)."""
    not_implemented("M1")


def decrypt_for_user(user_id: int, field: str, ciphertext: bytes) -> bytes:
    """Reverse of encrypt_for_user. Raises if the value belongs to another user or field."""
    not_implemented("M1")


def keyed_hash(value: str) -> bytes:
    """HMAC-SHA256 with settings.hmac_key, for looking up an email address without storing it readable."""
    not_implemented("M1")
