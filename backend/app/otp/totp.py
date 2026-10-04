"""Authenticator-app codes (RFC 6238; §4.3, §6.2, §7.6).  Owner: M2"""
import hmac
from dataclasses import dataclass

import pyotp
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session as Db

from app.core.config import get_settings
from app.core.crypto import decrypt_for_user, encrypt_for_user
from app.core.db import utc_now
from app.core.errors import AppError
from app.core.policy import TOTP_DIGITS, TOTP_PERIOD_SECONDS, TOTP_VALID_WINDOW
from app.models import SecondFactor, User
from app.otp.codes import group, is_digits, normalize

APP = "app"
SECRET_FIELD = "app_secret"  # associated data for encrypt_for_user (S4)


@dataclass
class TotpEnrolment:
    otpauth_uri: str  # opens the authenticator app directly: offered first (§7.6)
    secret_grouped: str  # copyable text in groups of four, for copying and speech


def active_app(db: Db, user: User) -> SecondFactor | None:
    """The confirmed app that is not reported lost: the only one whose codes are accepted."""
    return db.scalar(
        select(SecondFactor).where(
            SecondFactor.user_id == user.id,
            SecondFactor.type == APP,
            SecondFactor.confirmed_at.is_not(None),
            SecondFactor.suspended_at.is_(None),
        )
    )


def _pending_app(db: Db, user: User) -> SecondFactor | None:
    return db.scalar(
        select(SecondFactor)
        .where(SecondFactor.user_id == user.id, SecondFactor.type == APP, SecondFactor.confirmed_at.is_(None))
        .order_by(SecondFactor.id.desc())
    )


def _totp(user: User, factor: SecondFactor) -> pyotp.TOTP:
    secret = decrypt_for_user(user.id, SECRET_FIELD, factor.app_secret_encrypted).decode()
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS)


def _matching_step(user: User, factor: SecondFactor, code: str) -> int | None:
    """The time step within ±TOTP_VALID_WINDOW whose code equals `code`, newest first."""
    code = normalize(code)
    if not is_digits(code, TOTP_DIGITS):
        return None
    totp = _totp(user, factor)
    now_step = int(utc_now().timestamp()) // TOTP_PERIOD_SECONDS
    found = None
    for step in range(now_step + TOTP_VALID_WINDOW, now_step - TOTP_VALID_WINDOW - 1, -1):
        # Compare every step, so the time taken does not depend on which one matched.
        if hmac.compare_digest(totp.generate_otp(step), code) and found is None:
            found = step
    return found


def _claim_step(db: Db, factor: SecondFactor, step: int) -> bool:
    """Record the step in the same statement that checks it is newer than the last one (§6.2),
    so two copies of one code sent at the same moment cannot both be accepted."""
    result = db.execute(
        update(SecondFactor)
        .where(
            SecondFactor.id == factor.id,
            or_(SecondFactor.last_code_step.is_(None), SecondFactor.last_code_step < step),
        )
        .values(last_code_step=step)
    )
    db.commit()
    return result.rowcount == 1


def start_enrolment(db: Db, user: User) -> TotpEnrolment:
    """New random secret, stored encrypted (M1's encrypt_for_user), unconfirmed until one correct code."""
    if active_app(db, user) is not None:
        raise AppError(
            409, "already_set_up",
            "An authenticator app is already set up. Remove it on Manage factors before setting up a new one.",
        )
    for old in db.scalars(
        select(SecondFactor).where(
            SecondFactor.user_id == user.id, SecondFactor.type == APP, SecondFactor.confirmed_at.is_(None)
        )
    ):
        db.delete(old)

    secret = pyotp.random_base32(32)  # 160 bits, as RFC 4226 recommends
    db.add(
        SecondFactor(
            user_id=user.id,
            type=APP,
            label="Authenticator app",
            app_secret_encrypted=encrypt_for_user(user.id, SECRET_FIELD, secret.encode()),
        )
    )
    db.commit()
    uri = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS).provisioning_uri(
        name=user.username, issuer_name=get_settings().rp_name
    )
    return TotpEnrolment(otpauth_uri=uri, secret_grouped=group(secret, 4))


def confirm_enrolment(db: Db, user: User, code: str) -> bool:
    """§4.3: set-up is complete only when one correct code comes back."""
    factor = _pending_app(db, user)
    if factor is None:
        return False
    step = _matching_step(user, factor, code)
    if step is None or not _claim_step(db, factor, step):
        return False
    factor.confirmed_at = utc_now()
    db.commit()
    return True


def verify_code(db: Db, user: User, code: str) -> bool:
    """±TOTP_VALID_WINDOW steps; refuse a code from last_code_step or earlier (replay, §6.2)."""
    factor = active_app(db, user)
    if factor is None:
        return False
    step = _matching_step(user, factor, code)
    return step is not None and _claim_step(db, factor, step)
