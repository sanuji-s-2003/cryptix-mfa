"""Sending email.  Owner: M2

Used by M1 (address confirmation), M2 (login codes) and M5 (recovery codes,
cancel links). With EMAIL_MODE=console the message is printed to the server
log instead of being sent, so nobody needs a mail account to develop.
"""
from app.core.errors import not_implemented


def send_email(to: str, subject: str, body: str) -> None:
    """Plain-text email: every message must make sense read by a screen reader (§7)."""
    not_implemented("M2")
