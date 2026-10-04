"""Request and response bodies for M3's endpoints.  Owner: M3"""
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import AuthResponse


class PasskeyOptionsResponse(AuthResponse):
    options: dict = Field(description="PublicKeyCredentialCreationOptions or RequestOptions, as JSON")


class PasskeyVerifyRequest(BaseModel):
    credential: dict = Field(description="The browser's PublicKeyCredential, as JSON")
    label: str | None = Field(default=None, max_length=64)


class CredentialSummary(BaseModel):
    id: int
    label: str | None
    created_at: datetime
    suspended: bool


class CredentialListResponse(AuthResponse):
    credentials: list[CredentialSummary]
