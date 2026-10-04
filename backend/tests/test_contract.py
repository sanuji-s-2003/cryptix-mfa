"""Checks that the agreed contract is still in place.  [SHARED contract file]

If one of these fails, someone changed or removed something other members
depend on. Fix the change, don't edit the test, unless the whole group agreed
to update docs/api-contract.md.
"""
import pytest

from app.main import app

APPENDIX_B = [
    ("POST", "/api/register"), ("POST", "/api/email/verify"), ("POST", "/api/email/resend"),
    ("POST", "/api/login"), ("POST", "/api/logout"), ("GET", "/api/auth/status"),
    ("POST", "/api/mfa/totp/enroll"), ("POST", "/api/mfa/totp/confirm"), ("POST", "/api/mfa/totp/verify"),
    ("POST", "/api/mfa/totp/lost"), ("DELETE", "/api/mfa/totp"),
    ("POST", "/api/mfa/email/send"), ("POST", "/api/mfa/email/verify"), ("POST", "/api/mfa/restricted/hold"),
    ("POST", "/api/mfa/backup/generate"), ("POST", "/api/mfa/backup/verify"),
    ("POST", "/api/webauthn/register/options"), ("POST", "/api/webauthn/register/verify"),
    ("POST", "/api/webauthn/login/options"), ("POST", "/api/webauthn/login/verify"),
    ("GET", "/api/webauthn/credentials"), ("POST", "/api/webauthn/credentials/{credential_id}/lost"),
    ("DELETE", "/api/webauthn/credentials/{credential_id}"),
    ("POST", "/api/device/remember"), ("POST", "/api/device/verify"), ("DELETE", "/api/device"),
    ("POST", "/api/recovery/start"), ("POST", "/api/recovery/verify"), ("GET", "/api/mfa/cancel/{token}"),
]


@pytest.mark.parametrize("method,path", APPENDIX_B)
def test_every_appendix_b_endpoint_exists(method, path):
    assert method.lower() in app.openapi()["paths"].get(path, {})


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_invalid_input_is_a_full_sentence(client):
    r = client.post("/api/login", json={})
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "invalid_input"
    assert body["message"].endswith(".")
    assert set(body["fields"]) == {"username", "secret"}


def test_client_pages_are_served(client):
    for page in ("/", "/login.html", "/register.html"):
        r = client.get(page)
        assert r.status_code == 200
        assert '<main id="main"' in r.text
