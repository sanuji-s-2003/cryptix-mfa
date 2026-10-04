"""Backup codes: ten 20-digit single-use codes (§4.3, FR4, §7.6).  Owner: M2"""
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session as Db

from app.core.db import utc_now
from app.core.policy import BACKUP_CODE_COUNT, BACKUP_CODE_DIGITS, BACKUP_CODE_GROUP
from app.models import BackupCode, User
from app.otp.codes import check_code, group, hash_code, is_digits, normalize, random_digits


def generate(db: Db, user: User) -> list[str]:
    """Replace any old set. Store only Argon2id hashes; return the codes once, in groups of four digits."""
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    codes = [random_digits(BACKUP_CODE_DIGITS) for _ in range(BACKUP_CODE_COUNT)]
    db.add_all(BackupCode(user_id=user.id, code_hash=hash_code(code)) for code in codes)
    db.commit()
    return [group(code, BACKUP_CODE_GROUP) for code in codes]


def verify(db: Db, user: User, code: str) -> bool:
    """Accept an unused code once and mark it used."""
    code = normalize(code)
    if not is_digits(code, BACKUP_CODE_DIGITS):
        return False
    unused = db.scalars(select(BackupCode).where(BackupCode.user_id == user.id, BackupCode.used_at.is_(None))).all()
    match = None
    for row in unused:  # check every code, so the time taken does not show which one matched
        if check_code(row.code_hash, code) and match is None:
            match = row
    if match is None:
        return False
    # Mark used in the same statement that checks it is unused (§6.2): of two copies, only one wins.
    result = db.execute(
        update(BackupCode).where(BackupCode.id == match.id, BackupCode.used_at.is_(None)).values(used_at=utc_now())
    )
    db.commit()
    return result.rowcount == 1


def remaining(db: Db, user: User) -> int:
    """How many unused codes the user has left (FR4)."""
    return db.scalar(
        select(func.count()).select_from(BackupCode).where(BackupCode.user_id == user.id, BackupCode.used_at.is_(None))
    )
