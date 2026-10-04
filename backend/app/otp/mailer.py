"""Sending email.  Owner: M2

Used by M1 (address confirmation), M2 (login codes) and M5 (recovery codes,
cancel links). With EMAIL_MODE=console the message is printed to the server
log instead of being sent, so nobody needs a mail account to develop.
"""
import smtplib
import ssl
from email.message import EmailMessage

from app.core.config import get_settings
from app.core.errors import AppError


def send_email(to: str, subject: str, body: str) -> None:
    """Plain-text email: every message must make sense read by a screen reader (§7)."""
    settings = get_settings()
    if settings.email_mode == "console":
        line = "-" * 60
        print(f"\n{line}\nEMAIL (console mode, not sent)\nTo: {to}\nSubject: {subject}\n\n{body}\n{line}\n", flush=True)
        return

    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise AppError(
            503, "email_failed", "We could not send the email just now. Wait a few minutes and try again."
        ) from exc
