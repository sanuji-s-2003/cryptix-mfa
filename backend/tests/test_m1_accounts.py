"""Unit tests for M1's slice: passwords, sessions, crypto, /register, /email/*, /login, /logout.  Owner: M1

M5's orchestrator functions are replaced with fakes here (CONTRIBUTING.md §3), so these tests
check M1's own behaviour only. M2's email codes and mailer are real, except that sending is captured.
"""
import hashlib
import re
from datetime import timedelta

import pytest
from cryptography.exceptions import InvalidTag
from fastapi import Response
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from app.accounts import router as accounts_router
from app.accounts.passwords import hash_secret, validate_new_secret, verify_secret
from app.accounts.sessions import (
    SESSION_COOKIE,
    create_session,
    end_all_sessions,
    end_session,
    load_session,
    rotate_session_id,
)
from app.core.crypto import decrypt_for_user, encrypt_for_user, keyed_hash
from app.core.db import utc_now
from app.core.errors import AppError
from app.core.policy import SESSION_ABSOLUTE_HOURS, SESSION_IDLE_MINUTES
from app.main import app
from app.models import AuthSession, User
from app.schemas.common import AuthResponse, NextStep, SessionState

GOOD_PASSWORD = "correct horse battery staple"


# ---------- fakes for other members' functions ----------


@pytest.fixture
def audited(monkeypatch):
    events = []
    monkeypatch.setattr(
        accounts_router, "audit", lambda db, event, outcome, *, user_id=None, ip=None: events.append((event, outcome))
    )
    return events


@pytest.fixture
def lockout(monkeypatch):
    calls = {"failures": 0}

    def record_failure(db, user_id, ip):
        calls["failures"] += 1
        return 5 - calls["failures"]

    monkeypatch.setattr(accounts_router, "check_lockout", lambda db, user_id, ip: None)
    monkeypatch.setattr(accounts_router, "record_failure", record_failure)
    monkeypatch.setattr(accounts_router, "record_success", lambda db, user_id: None)
    return calls


@pytest.fixture
def fake_factor1(monkeypatch):
    def complete_factor1(db, request, response, user):
        create_session(db, response, user.id, SessionState.FACTOR1_PASSED)
        return AuthResponse(state=SessionState.FACTOR1_PASSED, next=NextStep.LOGIN_STEP2, message="Step 2 of 2.")

    monkeypatch.setattr(accounts_router, "complete_factor1", complete_factor1)


@pytest.fixture
def fake_require_state():
    """Stand-in for M5's require_state: any live session (loaded with M1's own load_session)."""

    def dependency(request: Request):
        from app.core.db import SessionLocal

        with SessionLocal() as db:
            session = load_session(db, request)
        if session is None:
            raise AppError(401, "not_signed_in", "You are not signed in. Sign in and try again.")
        return session

    app.dependency_overrides[accounts_router.SIGNED_IN_OR_RESTRICTED] = dependency


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr("app.otp.email_codes.send_email", lambda to, subject, body: sent.append((to, subject, body)))
    return sent


@pytest.fixture
def https_client():
    """The session cookie is Secure, so the test client must use https to send it back (§6.6)."""
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client


@pytest.fixture
def m5(audited, lockout, fake_factor1, fake_require_state):
    return audited


def emailed_code(sent) -> str:
    return re.search(r"is: ([\d ]+)\n", sent[-1][2]).group(1).replace(" ", "")


def register(client, username="alice", email="Alice@Example.com", secret=GOOD_PASSWORD, kind="password"):
    return client.post(
        "/api/register", json={"username": username, "email": email, "secret": secret, "secret_kind": kind}
    )


def fake_request(cookie: str | None = None) -> Request:
    headers = [(b"cookie", f"{SESSION_COOKIE}={cookie}".encode())] if cookie else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


def cookie_from(response: Response) -> str:
    header = response.headers["set-cookie"]
    return re.search(rf"{SESSION_COOKIE}=([^;]+)", header).group(1)


@pytest.fixture
def user(db):
    u = User(username="bob", password_hash=hash_secret(GOOD_PASSWORD), secret_kind="password")
    db.add(u)
    db.commit()
    return u


# ---------- crypto ----------


def test_encryption_round_trip_with_fresh_nonce():
    a = encrypt_for_user(1, "email", b"alice@example.com")
    b = encrypt_for_user(1, "email", b"alice@example.com")
    assert a != b and b"alice" not in a
    assert decrypt_for_user(1, "email", a) == b"alice@example.com"


@pytest.mark.parametrize("user_id,field", [(2, "email"), (1, "app_secret")])
def test_value_copied_to_another_user_or_field_fails(user_id, field):
    """S4: the associated data binds the value to its user and field."""
    sealed = encrypt_for_user(1, "email", b"alice@example.com")
    with pytest.raises(InvalidTag):
        decrypt_for_user(user_id, field, sealed)


def test_tampered_ciphertext_fails():
    sealed = bytearray(encrypt_for_user(1, "email", b"alice@example.com"))
    sealed[-1] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_for_user(1, "email", bytes(sealed))


def test_keyed_hash_is_stable_and_keyed():
    assert keyed_hash("a@example.com") == keyed_hash("a@example.com")
    assert keyed_hash("a@example.com") != keyed_hash("b@example.com")
    assert keyed_hash("a@example.com") != hashlib.sha256(b"a@example.com").digest()
    assert len(keyed_hash("a@example.com")) == 32


# ---------- passwords and PINs ----------


@pytest.mark.parametrize(
    "secret,kind",
    [("short1!", "password"), ("football", "password"), ("12345", "pin"), ("12ab56", "pin"), ("123456", "pin")],
)
def test_weak_secrets_are_refused_with_a_sentence(secret, kind):
    with pytest.raises(AppError) as exc:
        validate_new_secret(secret, kind)
    assert exc.value.status_code == 422
    assert exc.value.body.error == "weak_secret"
    assert exc.value.body.fields == ["secret"]
    assert exc.value.body.message.endswith(".")


def test_common_password_check_ignores_case():
    with pytest.raises(AppError):
        validate_new_secret("PassWord1", "password")


@pytest.mark.parametrize("secret,kind", [(GOOD_PASSWORD, "password"), ("Tr0ub4dor&3x", "password"), ("830164", "pin")])
def test_good_secrets_pass(secret, kind):
    validate_new_secret(secret, kind)


def test_hash_is_salted_argon2id():
    a, b = hash_secret(GOOD_PASSWORD), hash_secret(GOOD_PASSWORD)
    assert a.startswith("$argon2id$")
    assert a != b
    assert GOOD_PASSWORD not in a


def test_verify_secret():
    stored = hash_secret(GOOD_PASSWORD)
    assert verify_secret(stored, GOOD_PASSWORD)
    assert not verify_secret(stored, "wrong password")
    assert not verify_secret(None, GOOD_PASSWORD)
    assert not verify_secret("not a hash", GOOD_PASSWORD)


# ---------- sessions ----------


def test_session_cookie_is_random_and_only_its_hash_is_stored(db, user):
    response = Response()
    session = create_session(db, response, user.id, SessionState.RESTRICTED)
    header = response.headers["set-cookie"].lower()
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in header
    raw = cookie_from(response)
    assert len(raw) >= 43  # 32 random bytes
    assert session.session_id_hash == hashlib.sha256(raw.encode()).digest()
    assert session.state == "restricted"
    assert session.csrf_token
    assert session.expires_at - session.created_at == timedelta(hours=SESSION_ABSOLUTE_HOURS)


def test_load_session(db, user):
    response = Response()
    create_session(db, response, user.id, SessionState.RESTRICTED)
    assert load_session(db, fake_request(cookie_from(response))).user_id == user.id
    assert load_session(db, fake_request()) is None
    assert load_session(db, fake_request("made-up-session-id")) is None


def test_idle_session_is_refused_and_deleted(db, user, monkeypatch):
    response = Response()
    create_session(db, response, user.id, SessionState.AUTHENTICATED)
    later = utc_now() + timedelta(minutes=SESSION_IDLE_MINUTES, seconds=1)
    monkeypatch.setattr("app.accounts.sessions.utc_now", lambda: later)
    assert load_session(db, fake_request(cookie_from(response))) is None
    assert db.scalar(select(AuthSession)) is None


def test_activity_keeps_session_alive_until_absolute_limit(db, user, monkeypatch):
    response = Response()
    create_session(db, response, user.id, SessionState.AUTHENTICATED)
    cookie = cookie_from(response)
    start = utc_now()
    # Active every 20 minutes: never idle, but refused once 12 hours have passed.
    for minutes in range(20, SESSION_ABSOLUTE_HOURS * 60, 20):
        monkeypatch.setattr("app.accounts.sessions.utc_now", lambda m=minutes: start + timedelta(minutes=m))
        assert load_session(db, fake_request(cookie)) is not None
    monkeypatch.setattr("app.accounts.sessions.utc_now", lambda: start + timedelta(hours=SESSION_ABSOLUTE_HOURS))
    assert load_session(db, fake_request(cookie)) is None


def test_rotation_gives_new_id_and_old_one_stops_working(db, user):
    """ST9: an ID captured or planted before a step is useless afterwards (§4.7)."""
    first = Response()
    session = create_session(db, first, user.id, SessionState.FACTOR1_PASSED)
    old_cookie, created, expires, csrf = cookie_from(first), session.created_at, session.expires_at, session.csrf_token

    second = Response()
    rotated = rotate_session_id(db, second, session)
    new_cookie = cookie_from(second)
    assert new_cookie != old_cookie
    assert load_session(db, fake_request(old_cookie)) is None
    loaded = load_session(db, fake_request(new_cookie))
    assert loaded.session_id_hash == rotated.session_id_hash
    assert (loaded.user_id, loaded.state, loaded.csrf_token) == (user.id, "factor1_passed", csrf)
    assert (loaded.created_at, loaded.expires_at) == (created, expires)
    assert len(db.scalars(select(AuthSession)).all()) == 1


def test_end_session_deletes_record_and_clears_cookie(db, user):
    response = Response()
    session = create_session(db, response, user.id, SessionState.AUTHENTICATED)
    cookie = cookie_from(response)
    out = Response()
    end_session(db, out, session)
    assert f'{SESSION_COOKIE}=""' in out.headers["set-cookie"] or "Max-Age=0" in out.headers["set-cookie"]
    assert load_session(db, fake_request(cookie)) is None


def test_end_all_sessions_only_for_that_user(db, user):
    other = User(username="carol", password_hash="x", secret_kind="password")
    db.add(other)
    db.commit()
    for owner in (user, user, other):
        create_session(db, Response(), owner.id, SessionState.AUTHENTICATED)
    end_all_sessions(db, user.id)
    assert [s.user_id for s in db.scalars(select(AuthSession))] == [other.id]


# ---------- /register and /email/* ----------


def test_register_creates_restricted_account(https_client, db, m5, outbox):
    r = register(https_client)
    assert r.status_code == 201, r.json()
    body = r.json()
    assert (body["state"], body["next"]) == ("restricted", "choose_factor")
    assert body["message"].endswith(".")
    assert SESSION_COOKIE in r.cookies

    user = db.scalar(select(User))
    assert user.username == "alice" and user.secret_kind == "password"
    assert user.password_hash.startswith("$argon2id$")
    assert b"alice@example.com" not in user.email_encrypted
    assert decrypt_for_user(user.id, "email", user.email_encrypted) == b"alice@example.com"
    assert user.email_lookup_hash == keyed_hash("alice@example.com")
    assert user.email_confirmed_at is None
    assert db.scalar(select(AuthSession)).state == "restricted"
    assert outbox[-1][0] == "alice@example.com"
    assert ("register", "success") in m5


def test_register_with_pin(https_client, db, m5, outbox):
    assert register(https_client, secret="830164", kind="pin").status_code == 201
    assert db.scalar(select(User)).secret_kind == "pin"


def test_register_refuses_weak_secret(https_client, db, m5, outbox):
    r = register(https_client, secret="password")
    assert r.status_code == 422 and r.json()["error"] == "weak_secret"
    assert db.scalar(select(User)) is None


def test_register_refuses_bad_email(https_client, m5, outbox):
    r = register(https_client, email="not-an-address")
    assert r.status_code == 422 and r.json()["fields"] == ["email"]


def test_register_refuses_taken_username_and_email(https_client, m5, outbox):
    assert register(https_client).status_code == 201
    r = register(https_client, email="other@example.com")
    assert r.status_code == 409 and r.json()["error"] == "username_taken"
    r = register(https_client, username="alice2", email=" ALICE@example.com ")
    assert r.status_code == 409 and r.json()["error"] == "email_taken"


def test_confirm_email(https_client, db, m5, lockout, outbox):
    register(https_client)
    wrong = https_client.post("/api/email/verify", json={"code": "0000 0000"})
    assert wrong.status_code == 401
    assert wrong.json()["error"] == "not_accepted" and wrong.json()["tries_left"] == 4

    r = https_client.post("/api/email/verify", json={"code": emailed_code(outbox)})
    assert r.status_code == 200, r.json()
    assert r.json()["state"] == "restricted"
    assert db.scalar(select(User)).email_confirmed_at is not None
    assert ("email.confirm", "failure") in m5 and ("email.confirm", "success") in m5

    again = https_client.post("/api/email/verify", json={"code": emailed_code(outbox)})
    assert again.status_code == 200 and "already confirmed" in again.json()["message"]


def test_resend_replaces_the_code(https_client, db, m5, outbox):
    register(https_client)
    first = emailed_code(outbox)
    r = https_client.post("/api/email/resend")
    assert r.status_code == 202
    second = emailed_code(outbox)
    assert len(outbox) == 2
    if first != second:
        assert https_client.post("/api/email/verify", json={"code": first}).status_code == 401
    assert https_client.post("/api/email/verify", json={"code": second}).status_code == 200


def test_email_endpoints_need_a_session(https_client, m5):
    assert https_client.post("/api/email/resend").status_code == 401


# ---------- /login and /logout ----------


def test_login_correct_password(https_client, user, m5):
    r = https_client.post("/api/login", json={"username": "bob", "secret": GOOD_PASSWORD})
    assert r.status_code == 200, r.json()
    assert (r.json()["state"], r.json()["next"]) == ("factor1_passed", "login_step2")
    assert ("login.factor1", "success") in m5


def test_wrong_password_and_unknown_user_look_the_same(https_client, user, m5, lockout):
    """SR-8: same status and body; tries_left comes from M5 either way."""
    wrong = https_client.post("/api/login", json={"username": "bob", "secret": "wrong password"})
    lockout["failures"] = 0
    unknown = https_client.post("/api/login", json={"username": "nobody", "secret": "wrong password"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert wrong.json()["error"] == "not_accepted"
    assert wrong.json()["message"] == "Not accepted. 4 tries left."


def test_login_checks_lockout_first(https_client, user, m5, monkeypatch):
    def locked(db, user_id, ip):
        raise AppError(423, "locked", "Too many tries. Wait one minute, then try again.")

    monkeypatch.setattr(accounts_router, "check_lockout", locked)
    monkeypatch.setattr(accounts_router, "verify_secret", lambda *a: pytest.fail("checked password while locked"))
    r = https_client.post("/api/login", json={"username": "bob", "secret": GOOD_PASSWORD})
    assert r.status_code == 423


def test_logout_deletes_session(https_client, db, user, m5):
    https_client.post("/api/login", json={"username": "bob", "secret": GOOD_PASSWORD})
    old_cookie = https_client.cookies.get(SESSION_COOKIE)
    assert db.scalar(select(AuthSession)) is not None

    r = https_client.post("/api/logout")
    assert r.status_code == 200
    assert (r.json()["state"], r.json()["next"]) == ("anonymous", "login_step1")
    assert db.scalar(select(AuthSession)) is None
    assert ("logout", "success") in m5

    # ST9: the copied ID no longer works anywhere.
    assert load_session(db, fake_request(old_cookie)) is None


def test_logout_without_session_is_fine(https_client, m5):
    r = https_client.post("/api/logout")
    assert r.status_code == 200 and r.json()["state"] == "anonymous"


@pytest.mark.parametrize("username", ["   ", "  ab  "])
def test_username_too_short_after_trimming(https_client, m5, outbox, username):
    r = register(https_client, username=username)
    assert r.status_code == 422 and r.json()["fields"] == ["username"]


def test_spaces_around_username_are_ignored_but_kept_in_secret(https_client, db, m5, outbox):
    assert register(https_client, username="  alice  ", secret=f" {GOOD_PASSWORD} ").status_code == 201
    assert db.scalar(select(User)).username == "alice"
    r = https_client.post("/api/login", json={"username": " alice ", "secret": f" {GOOD_PASSWORD} "})
    assert r.status_code == 200
    r = https_client.post("/api/login", json={"username": "alice", "secret": GOOD_PASSWORD})
    assert r.status_code == 401


def test_register_ends_the_session_this_browser_had(https_client, db, m5, outbox):
    register(https_client)
    old_cookie = https_client.cookies.get(SESSION_COOKIE)
    register(https_client, username="alice2", email="alice2@example.com")
    assert load_session(db, fake_request(old_cookie)) is None
    assert len(db.scalars(select(AuthSession)).all()) == 1
