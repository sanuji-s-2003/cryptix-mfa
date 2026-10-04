"""Emailed one-time codes, each bound to one purpose (§1.6, §5.4, S2, SR-3).  Owner: M2"""
from datetime import timedelta
from enum import Enum

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as Db

from app.core.crypto import decrypt_for_user
from app.core.db import utc_now
from app.core.policy import EMAIL_CODE_DIGITS, EMAIL_CODE_RETAIN_HOURS_AFTER_EXPIRY, EMAIL_CODE_TTL_MINUTES
from app.models import EmailCode, User
from app.otp.codes import check_code, group, hash_code, is_digits, normalize, random_digits
from app.otp.mailer import send_email

EMAIL_FIELD = "email"  # associated data M1 uses for User.email_encrypted (S4)


class EmailPurpose(str, Enum):
    CONFIRM_EMAIL = "confirm_email"  # M1, registration
    LOGIN = "login"  # M2, weak route to Restricted
    RECOVERY = "recovery"  # M5, forgotten password


_MESSAGES = {
    EmailPurpose.CONFIRM_EMAIL: (
        "Confirm your email address for Cryptix",
        "Your code to confirm this email address for Cryptix is",
        "If you did not create a Cryptix account, you can ignore this email.",
    ),
    EmailPurpose.LOGIN: (
        "Your Cryptix sign-in code",
        "Your Cryptix sign-in code is",
        "This code signs you in to a restricted session only. If you did not try to sign in, "
        "someone knows your password: reset it as soon as you can.",
    ),
    EmailPurpose.RECOVERY: (
        "Your Cryptix password reset code",
        "Your code to reset your Cryptix password is",
        "If you did not ask to reset your password, you can ignore this email. Your password has not changed.",
    ),
}


def _email_address(user: User) -> str:
    return decrypt_for_user(user.id, EMAIL_FIELD, user.email_encrypted).decode()


def issue_email_code(db: Db, user: User, purpose: EmailPurpose) -> None:
    """Generate an EMAIL_CODE_DIGITS code, store only its hash with purpose and expiry, email it.

    An address that is not yet confirmed is used only to confirm it (Fig. 4): for any other purpose
    nothing is sent, and the caller answers exactly as if it had been (SR-8).
    """
    if user.email_encrypted is None or (purpose != EmailPurpose.CONFIRM_EMAIL and user.email_confirmed_at is None):
        return
    now = utc_now()
    # §8.5: keep a code no longer than an hour after it expires.
    db.execute(
        delete(EmailCode).where(
            EmailCode.expires_at < now - timedelta(hours=EMAIL_CODE_RETAIN_HOURS_AFTER_EXPIRY)
        )
    )
    # A new code replaces any earlier unused one for the same purpose.
    db.execute(
        update(EmailCode)
        .where(EmailCode.user_id == user.id, EmailCode.purpose == purpose.value, EmailCode.used_at.is_(None))
        .values(used_at=now)
    )
    code = random_digits(EMAIL_CODE_DIGITS)
    db.add(
        EmailCode(
            user_id=user.id,
            purpose=purpose.value,
            code_hash=hash_code(code),
            expires_at=now + timedelta(minutes=EMAIL_CODE_TTL_MINUTES),
        )
    )
    db.commit()

    subject, intro, outro = _MESSAGES[purpose]
    body = (
        f"Hello {user.username},\n\n"
        f"{intro}: {group(code, 4)}\n\n"
        f"The code has {EMAIL_CODE_DIGITS} digits. It works once, for the next {EMAIL_CODE_TTL_MINUTES} minutes.\n\n"
        f"{outro}\n\nCryptix\n"
    )
    send_email(_email_address(user), subject, body)


def verify_email_code(db: Db, user: User, purpose: EmailPurpose, code: str) -> bool:
    """Accept once: mark used in the same database operation that checks it was unused (§6.2).
    A code issued for another purpose is refused (S2)."""
    code = normalize(code)
    if not is_digits(code, EMAIL_CODE_DIGITS):
        return False
    now = utc_now()
    row = db.scalar(
        select(EmailCode)
        .where(
            EmailCode.user_id == user.id,
            EmailCode.purpose == purpose.value,
            EmailCode.used_at.is_(None),
            EmailCode.expires_at > now,
        )
        .order_by(EmailCode.id.desc())
    )
    if row is None or not check_code(row.code_hash, code):
        return False
    result = db.execute(
        update(EmailCode).where(EmailCode.id == row.id, EmailCode.used_at.is_(None)).values(used_at=now)
    )
    db.commit()
    return result.rowcount == 1
