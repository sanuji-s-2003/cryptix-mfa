"""Shared test fixtures.  [SHARED contract file]

Tests run against a throwaway SQLite file, or PostgreSQL when TEST_DATABASE_URL
is set (CI does this). To test your slice before another member has built the
function you call, replace it with monkeypatch or app.dependency_overrides.
"""
import base64
import os
import secrets
import tempfile
from pathlib import Path

os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", f"sqlite:///{Path(tempfile.mkdtemp()) / 'test.db'}"
)
os.environ["DATA_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
os.environ["HMAC_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
os.environ["EMAIL_MODE"] = "console"
os.environ["FORCE_HTTPS"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import models  # noqa: E402,F401
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_database():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session
