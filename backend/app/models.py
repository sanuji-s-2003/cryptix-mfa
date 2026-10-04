"""Database tables.  [SHARED contract file]

Figures 8 and 9 of the design, plus the columns and tables the implementation
needs that the figures do not show. Each addition is marked "+" and listed in
docs/implementation-assumptions.md (IA-4) so the report can state it.

Every member reads and writes these tables, so nobody edits this file alone:
a change needs approval from each member who uses the table (CONTRIBUTING.md).
"""
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base, UTCDateTime, utc_now


class User(Base):
    """USER, Fig. 8. Written by M1."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))  # Argon2id, salted (§8.1)
    secret_kind: Mapped[str] = mapped_column(String(8))  # + "password" or "pin" (§4.2)
    email_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)  # bound to the user (§8.2, S4)
    email_lookup_hash: Mapped[bytes | None] = mapped_column(LargeBinary, index=True)  # + keyed hash (Appendix A)
    email_confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)  # +


class AuthSession(Base):
    """SESSION, Fig. 8. Rows created/rotated/deleted by M1; state and challenge set by M5.

    Named AuthSession so it is never confused with SQLAlchemy's Session.
    """

    __tablename__ = "sessions"

    session_id_hash: Mapped[bytes] = mapped_column(LargeBinary(32), primary_key=True)  # SHA-256 of the cookie
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)  # +
    state: Mapped[str] = mapped_column(String(32))  # SessionState, Fig. 3
    challenge: Mapped[bytes | None] = mapped_column(LargeBinary)  # single use: cleared when consumed
    challenge_purpose: Mapped[str | None] = mapped_column(String(16))  # login, setup, recovery
    challenge_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    csrf_token: Mapped[str] = mapped_column(String(64))  # + request token (§6.6)
    factor2_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # + last second-factor proof (SR-9)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)  # + 12 h absolute limit
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)  # + 30 min idle limit
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class AuditLog(Base):
    """AUDIT_LOG, Fig. 8. Append only (§8.5). Written only through M5's audit()."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    event: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16))
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)  # "appears in", Fig. 8
    ip: Mapped[str | None] = mapped_column(String(45))  # "the time and the address" (§8.4)


class SecondFactor(Base):
    """SECOND_FACTOR, Fig. 9. Rows with type "app" belong to M2, type "passkey" to M3."""

    __tablename__ = "second_factors"

    id: Mapped[int] = mapped_column(primary_key=True)  # +
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    type: Mapped[str] = mapped_column(String(8))  # "app" or "passkey"
    label: Mapped[str | None] = mapped_column(String(64))  # + name read out on Manage factors
    app_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)  # app only
    last_code_step: Mapped[int | None] = mapped_column(Integer)  # replay guard, app only (§6.2)
    passkey_public_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # passkey only, not secret
    passkey_credential_id: Mapped[bytes | None] = mapped_column(LargeBinary, unique=True)  # + passkey only
    passkey_sign_count: Mapped[int | None] = mapped_column(Integer)  # + passkey only
    passkey_transports: Mapped[str | None] = mapped_column(String(64))  # + passkey only, comma-separated
    confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # + app works only after one correct code (§4.3)
    suspended_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # set when reported lost
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)  # +


class BackupCode(Base):
    """BACKUP_CODE, Fig. 9. Written by M2."""

    __tablename__ = "backup_codes"

    id: Mapped[int] = mapped_column(primary_key=True)  # +
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(255))  # Argon2id, salted
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # single use


class EmailCode(Base):
    """+ Not drawn in Fig. 8/9. Emailed codes with their purpose (S2). Written by M2."""

    __tablename__ = "email_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))  # confirm_email, login, recovery
    code_hash: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)


class RememberedBrowser(Base):
    """+ Not drawn in Fig. 8/9. Remembered-browser tokens (§4.6, FR7). Written by M3."""

    __tablename__ = "remembered_browsers"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)


class LockoutCounter(Base):
    """+ Not drawn in Fig. 8/9. Failure counters per account and per address (§5.3). Written by M5."""

    __tablename__ = "lockout_counters"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)  # "user:<id>" or "ip:<address>"
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    total_failures: Mapped[int] = mapped_column(Integer, default=0)
    lock_level: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    hard_locked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    window_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class PendingChange(Base):
    """+ Not drawn in Fig. 8/9. 24-hour waiting periods with a cancel link (§5.4, SR-10). Written by M5."""

    __tablename__ = "pending_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # restricted_new_factor, delete_lost_factor
    second_factor_id: Mapped[int | None] = mapped_column(ForeignKey("second_factors.id"))
    cancel_token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    not_before: Mapped[datetime] = mapped_column(UTCDateTime)
    cancelled_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utc_now)
