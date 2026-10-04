"""Request and response bodies for M5's endpoints.  Owner: M5"""
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import AuthResponse


class StatusResponse(AuthResponse):
    username: str | None = None
    csrf_token: str | None = Field(default=None, description="Send back as X-CSRF-Token on every change")
    second_factor_options: list[str] = Field(
        default_factory=list,
        description='Only after Factor 1: any of "passkey", "app", "backup_code", "email"',
    )
    idle_seconds_left: int | None = None


class RecoveryStartRequest(BaseModel):
    username: str = Field(max_length=64)


class RecoveryVerifyRequest(BaseModel):
    username: str = Field(max_length=64)
    code: str = Field(min_length=1, max_length=64)
    new_secret: str = Field(min_length=1, max_length=256)
    secret_kind: Literal["password", "pin"]
