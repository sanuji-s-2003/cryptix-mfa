"""Database engine, session factory and UTC time helpers.  [SHARED contract file]"""
from collections.abc import Iterator
from datetime import datetime, timezone

from sqlalchemy import DateTime, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_url = get_settings().database_url
engine = create_engine(
    _url,
    connect_args={"check_same_thread": False} if _url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def utc_now() -> datetime:
    """Always use this, never datetime.now() or datetime.utcnow()."""
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores UTC and always returns timezone-aware datetimes, on SQLite as well as PostgreSQL."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            raise ValueError("Naive datetime: use app.core.db.utc_now()")
        return value.astimezone(timezone.utc) if value is not None else None

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


def init_db() -> None:
    """Create every table in app/models.py (A4: one server, one database, no migrations)."""
    from app import models  # noqa: F401  registers the tables on Base.metadata

    Base.metadata.create_all(engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one database session per request."""
    with SessionLocal() as db:
        yield db
