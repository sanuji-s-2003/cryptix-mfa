"""Settings read from environment variables and backend/.env.  [SHARED contract file]"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./cryptix-dev.db"

    # A5: keys live in a protected file outside the database, never in the DB or in git.
    data_key: str = ""  # base64, 32 bytes: AES-GCM key for stored secrets (§8.2)
    hmac_key: str = ""  # base64, 32 bytes: keyed hash for email lookup (Appendix A)

    rp_id: str = "localhost"
    rp_name: str = "Cryptix"
    origin: str = "http://localhost:8000"

    force_https: bool = False  # SR-1: true for the demo

    email_mode: str = "console"  # "console" prints emails to the server log; "smtp" sends them
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "Cryptix <no-reply@cryptix.local>"


@lru_cache
def get_settings() -> Settings:
    return Settings()
