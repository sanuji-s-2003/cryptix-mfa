"""Encryption and keyed hashing for stored values (§8.2, S4, D10).  Owner: M1

Used by M1 (email address) and M2 (authenticator-app secret). Keys come from
settings.data_key and settings.hmac_key, never from the database (A5).
Use the `cryptography` library only; no hand-written cryptography (§3.1).
"""
import base64
import binascii
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

NONCE_BYTES = 12  # 96-bit nonce, the size AES-GCM is designed for


def _key(name: str) -> bytes:
    """A 32-byte key from settings (base64). Refuse to run with a missing or short key."""
    value = getattr(get_settings(), name)
    try:
        key = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != 32:
        raise RuntimeError(
            f"{name.upper()} must be 32 random bytes in base64. See backend/.env.example for how to make one."
        )
    return key


def _associated_data(user_id: int, field: str) -> bytes:
    return f"{field}:{user_id}".encode()


def encrypt_for_user(user_id: int, field: str, plaintext: bytes) -> bytes:
    """AES-256-GCM with a fresh nonce. Associated data = f"{field}:{user_id}", so a value
    copied into another user's record fails to decrypt (S4)."""
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(_key("data_key")).encrypt(nonce, plaintext, _associated_data(user_id, field))


def decrypt_for_user(user_id: int, field: str, ciphertext: bytes) -> bytes:
    """Reverse of encrypt_for_user. Raises if the value belongs to another user or field."""
    nonce, sealed = ciphertext[:NONCE_BYTES], ciphertext[NONCE_BYTES:]
    return AESGCM(_key("data_key")).decrypt(nonce, sealed, _associated_data(user_id, field))


def keyed_hash(value: str) -> bytes:
    """HMAC-SHA256 with settings.hmac_key, for looking up an email address without storing it readable."""
    return hmac.new(_key("hmac_key"), value.encode(), hashlib.sha256).digest()
