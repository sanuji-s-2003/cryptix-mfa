"""Remembered browser: a convenience, never a factor (§4.6, FR7).  Owner: M3"""
from fastapi import Request, Response
from sqlalchemy.orm import Session as Db

from app.core.errors import not_implemented
from app.models import User

REMEMBER_COOKIE = "cryptix_device"


def remember_browser(db: Db, response: Response, user: User) -> None:
    """Random token for REMEMBER_BROWSER_DAYS; store only its hash."""
    not_implemented("M3")


def check_remembered_browser(db: Db, request: Request, response: Response, user: User) -> bool:
    """Valid for this user? Replace the token each time it is used (§6.2)."""
    not_implemented("M3")


def forget_browser(db: Db, request: Request, response: Response) -> None:
    not_implemented("M3")
