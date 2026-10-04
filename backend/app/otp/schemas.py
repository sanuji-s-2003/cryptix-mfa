"""Response bodies for M2's endpoints.  Owner: M2"""
from app.schemas.common import AuthResponse


class TotpEnrollResponse(AuthResponse):
    otpauth_uri: str
    secret_grouped: str


class BackupCodesResponse(AuthResponse):
    codes: list[str]
