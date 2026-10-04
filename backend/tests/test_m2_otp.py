"""Unit tests for M2's slice: TOTP, emailed codes, backup codes, mailer, /mfa/totp/*, /mfa/email/*, /mfa/backup/*.  Owner: M2

M1's crypto and M5's orchestrator functions are replaced with fakes here (CONTRIBUTING.md §3),
so these tests check M2's own behaviour only.
"""
import re
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from sqlalchemy import select

from app.core.db import utc_now
from app.core.policy import BACKUP_CODE_COUNT, TOTP_PERIOD_SECONDS
from app.main import app
from app.models import AuthSession, BackupCode, EmailCode, SecondFactor, User
from app.otp import backup_codes, mailer, totp
from app.otp.codes import group, normalize
from app.otp.email_codes import EmailPurpose, issue_email_code, verify_email_code
from app.otp.router import router as otp_router
from app.schemas.common import AuthResponse, NextStep, SessionState

T0 = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


# ---------- fakes for other members' functions ----------


def fake_encrypt(user_id, field, plaintext):
    return f"{field}:{user_id}:".encode() + plaintext


def fake_decrypt(user_id, field, ciphertext):
    prefix = f"{field}:{user_id}:".encode()
    assert ciphertext.startswith(prefix), "value belongs to another user or field"
    return ciphertext[len(prefix):]


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def advance(self, steps=1):
        self.now += timedelta(seconds=TOTP_PERIOD_SECONDS * steps)


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    for module in ("app.otp.totp", "app.otp.email_codes", "app.otp.backup_codes", "app.otp.router"):
        monkeypatch.setattr(f"{module}.utc_now", c)
    return c


@pytest.fixture
def sent(monkeypatch):
    outbox = []
    monkeypatch.setattr("app.otp.email_codes.send_email", lambda to, subject, body: outbox.append((to, subject, body)))
    return outbox


@pytest.fixture(autouse=True)
def fake_crypto(monkeypatch):
    monkeypatch.setattr("app.otp.totp.encrypt_for_user", fake_encrypt)
    monkeypatch.setattr("app.otp.totp.decrypt_for_user", fake_decrypt)
    monkeypatch.setattr("app.otp.email_codes.decrypt_for_user", fake_decrypt)


@pytest.fixture
def user(db):
    u = User(
        username="alice", password_hash="x", secret_kind="password",
        email_encrypted=fake_encrypt(1, "email", b"alice@example.com"), email_confirmed_at=T0,
    )
    db.add(u)
    db.commit()
    assert u.id == 1
    return u


def emailed_code(outbox) -> str:
    match = re.search(r"is: ([\d ]+)\n", outbox[-1][2])
    return match.group(1).replace(" ", "")


def app_code(db, user, clock, offset=0) -> str:
    factor = db.scalar(select(SecondFactor).where(SecondFactor.user_id == user.id).order_by(SecondFactor.id.desc()))
    secret = fake_decrypt(user.id, "app_secret", factor.app_secret_encrypted).decode()
    step = int(clock.now.timestamp()) // TOTP_PERIOD_SECONDS + offset
    return pyotp.TOTP(secret).generate_otp(step)


# ---------- helpers ----------


def test_normalize_strips_spaces_and_hyphens():
    assert normalize(" 1234-5678 9012 ") == "123456789012"


def test_group_in_fours():
    assert group("ABCDEFGHIJ", 4) == "ABCD EFGH IJ"


def test_console_mailer_prints(capsys):
    mailer.send_email("bob@example.com", "Hello", "Your code is 1234 5678.")
    out = capsys.readouterr().out
    assert "bob@example.com" in out and "Your code is 1234 5678." in out


# ---------- authenticator app ----------


def test_enrolment_gives_link_and_grouped_secret(db, user, clock):
    enrolment = totp.start_enrolment(db, user)
    assert enrolment.otpauth_uri.startswith("otpauth://totp/")
    assert "issuer=Cryptix" in enrolment.otpauth_uri
    assert re.fullmatch(r"([A-Z2-7]{4} ){7}[A-Z2-7]{4}", enrolment.secret_grouped)
    factor = db.scalar(select(SecondFactor))
    assert factor.confirmed_at is None


def test_unconfirmed_app_does_not_sign_in(db, user, clock):
    totp.start_enrolment(db, user)
    assert not totp.verify_code(db, user, app_code(db, user, clock))


def test_confirm_needs_correct_code(db, user, clock):
    totp.start_enrolment(db, user)
    assert not totp.confirm_enrolment(db, user, "000000" if app_code(db, user, clock) != "000000" else "111111")
    assert totp.confirm_enrolment(db, user, app_code(db, user, clock))
    assert db.scalar(select(SecondFactor)).confirmed_at is not None


def test_cannot_enrol_twice(db, user, clock):
    totp.start_enrolment(db, user)
    totp.confirm_enrolment(db, user, app_code(db, user, clock))
    with pytest.raises(Exception) as err:
        totp.start_enrolment(db, user)
    assert err.value.body.error == "already_set_up"


def test_restarting_enrolment_replaces_unconfirmed_secret(db, user, clock):
    totp.start_enrolment(db, user)
    totp.start_enrolment(db, user)
    assert len(db.scalars(select(SecondFactor)).all()) == 1


@pytest.fixture
def confirmed_app(db, user, clock):
    totp.start_enrolment(db, user)
    assert totp.confirm_enrolment(db, user, app_code(db, user, clock))
    clock.advance()
    return user


def test_st4_same_app_code_twice_is_refused(db, confirmed_app, clock):
    code = app_code(db, confirmed_app, clock)
    assert totp.verify_code(db, confirmed_app, code)
    assert not totp.verify_code(db, confirmed_app, code)


def test_older_code_refused_after_newer_one(db, confirmed_app, clock):
    clock.advance()
    newer, older = app_code(db, confirmed_app, clock), app_code(db, confirmed_app, clock, offset=-1)
    assert totp.verify_code(db, confirmed_app, newer)
    assert not totp.verify_code(db, confirmed_app, older)


def test_one_step_either_side_accepted(db, confirmed_app, clock):
    clock.advance(3)
    assert totp.verify_code(db, confirmed_app, app_code(db, confirmed_app, clock, offset=-1))
    clock.advance(3)
    assert totp.verify_code(db, confirmed_app, app_code(db, confirmed_app, clock, offset=1))


def test_code_two_steps_old_refused(db, confirmed_app, clock):
    clock.advance(3)
    assert not totp.verify_code(db, confirmed_app, app_code(db, confirmed_app, clock, offset=-2))


def test_app_code_with_space(db, confirmed_app, clock):
    code = app_code(db, confirmed_app, clock)
    assert totp.verify_code(db, confirmed_app, f"{code[:3]} {code[3:]}")


def test_lost_app_stops_working(db, confirmed_app, clock):
    db.scalar(select(SecondFactor)).suspended_at = utc_now()
    db.commit()
    assert not totp.verify_code(db, confirmed_app, app_code(db, confirmed_app, clock))


# ---------- backup codes ----------


def test_backup_codes_are_ten_grouped_digits_stored_hashed(db, user):
    codes = backup_codes.generate(db, user)
    assert len(codes) == BACKUP_CODE_COUNT == len(set(codes))
    assert all(re.fullmatch(r"(\d{4} ){4}\d{4}", c) for c in codes)
    stored = [row.code_hash for row in db.scalars(select(BackupCode))]
    assert all(h.startswith("$argon2id$") for h in stored)
    assert not any(c.replace(" ", "") in h for c in codes for h in stored)


def test_st4_backup_code_works_once(db, user):
    code = backup_codes.generate(db, user)[3]
    assert backup_codes.verify(db, user, code.replace(" ", "-"))
    assert not backup_codes.verify(db, user, code)
    assert backup_codes.remaining(db, user) == BACKUP_CODE_COUNT - 1


def test_new_set_replaces_old(db, user):
    old = backup_codes.generate(db, user)[0]
    backup_codes.generate(db, user)
    assert not backup_codes.verify(db, user, old)
    assert backup_codes.remaining(db, user) == BACKUP_CODE_COUNT


def test_wrong_backup_code(db, user):
    backup_codes.generate(db, user)
    assert not backup_codes.verify(db, user, "0" * 20)
    assert not backup_codes.verify(db, user, "12345")


# ---------- emailed codes ----------


def test_email_code_sent_and_stored_hashed(db, user, clock, sent):
    issue_email_code(db, user, EmailPurpose.LOGIN)
    to, subject, body = sent[-1]
    assert to == "alice@example.com"
    code = emailed_code(sent)
    assert len(code) == 8
    row = db.scalar(select(EmailCode))
    assert row.purpose == "login" and code not in row.code_hash
    assert row.expires_at == T0 + timedelta(minutes=10)


def test_email_code_works_once(db, user, clock, sent):
    issue_email_code(db, user, EmailPurpose.LOGIN)
    code = emailed_code(sent)
    assert verify_email_code(db, user, EmailPurpose.LOGIN, code)
    assert not verify_email_code(db, user, EmailPurpose.LOGIN, code)


def test_st6_recovery_code_refused_at_login(db, user, clock, sent):
    issue_email_code(db, user, EmailPurpose.RECOVERY)
    code = emailed_code(sent)
    assert not verify_email_code(db, user, EmailPurpose.LOGIN, code)
    assert verify_email_code(db, user, EmailPurpose.RECOVERY, code)


def test_expired_email_code_refused(db, user, clock, sent):
    issue_email_code(db, user, EmailPurpose.LOGIN)
    clock.now += timedelta(minutes=10, seconds=1)
    assert not verify_email_code(db, user, EmailPurpose.LOGIN, emailed_code(sent))


def test_new_email_code_replaces_old(db, user, clock, sent):
    issue_email_code(db, user, EmailPurpose.LOGIN)
    old = emailed_code(sent)
    issue_email_code(db, user, EmailPurpose.LOGIN)
    new = emailed_code(sent)
    assert not verify_email_code(db, user, EmailPurpose.LOGIN, old)
    assert verify_email_code(db, user, EmailPurpose.LOGIN, new)


def test_unconfirmed_address_used_only_for_confirmation(db, user, clock, sent):
    user.email_confirmed_at = None
    db.commit()
    issue_email_code(db, user, EmailPurpose.RECOVERY)
    assert sent == []
    issue_email_code(db, user, EmailPurpose.CONFIRM_EMAIL)
    assert len(sent) == 1


def test_old_email_codes_are_purged(db, user, clock, sent):
    issue_email_code(db, user, EmailPurpose.LOGIN)
    clock.now += timedelta(hours=2)
    issue_email_code(db, user, EmailPurpose.RECOVERY)
    assert [r.purpose for r in db.scalars(select(EmailCode))] == ["recovery"]


# ---------- endpoints ----------


class Orchestrator:
    """Stands in for M5 until the orchestrator is built."""

    def __init__(self):
        self.failures = 0
        self.successes = 0
        self.holds = []
        self.events = []

    def check_lockout(self, db, user_id, ip):
        pass

    def record_failure(self, db, user_id, ip):
        self.failures += 1
        return 5 - self.failures

    def record_success(self, db, user_id):
        self.successes += 1

    def audit(self, db, event, outcome, *, user_id=None, ip=None):
        self.events.append((event, outcome))

    def start_hold(self, db, user, kind, second_factor_id=None):
        self.holds.append((kind, second_factor_id))

    def complete_factor2(self, db, response, session, method):
        session.state = SessionState.AUTHENTICATED.value
        return AuthResponse(state=SessionState.AUTHENTICATED, next=NextStep.SIGNED_IN, message="You are signed in.")

    def enter_restricted(self, db, response, session):
        session.state = SessionState.RESTRICTED.value
        return AuthResponse(state=SessionState.RESTRICTED, next=NextStep.CHOOSE_FACTOR, message="Restricted.")


@pytest.fixture
def orch(monkeypatch):
    o = Orchestrator()
    for name in ("check_lockout", "record_failure", "record_success", "audit", "start_hold",
                 "complete_factor2", "enter_restricted"):
        monkeypatch.setattr(f"app.otp.router.{name}", getattr(o, name))
    return o


@pytest.fixture
def as_session(user):
    """Replace every M2 endpoint's session dependency with a session in the given state."""

    def use(state: SessionState) -> AuthSession:
        session = AuthSession(user_id=user.id, state=state.value)
        for route in otp_router.routes:
            for dep in route.dependant.dependencies:
                if dep.name == "session":
                    app.dependency_overrides[dep.call] = lambda: session
        return session

    return use


def test_app_setup_then_login(client, db, user, clock, orch, as_session):
    as_session(SessionState.RESTRICTED)
    r = client.post("/api/mfa/totp/enroll")
    assert r.status_code == 200, r.json()
    assert r.json()["otpauth_uri"].startswith("otpauth://") and r.json()["next"] == "setup"

    r = client.post("/api/mfa/totp/confirm", json={"code": app_code(db, user, clock)})
    assert r.status_code == 200 and r.json()["next"] == "backup_codes"

    clock.advance()
    as_session(SessionState.FACTOR1_PASSED)
    r = client.post("/api/mfa/totp/verify", json={"code": "not a code"})
    assert r.status_code == 401
    assert r.json()["error"] == "not_accepted" and r.json()["tries_left"] == 4
    r = client.post("/api/mfa/totp/verify", json={"code": app_code(db, user, clock)})
    assert r.status_code == 200 and r.json()["state"] == "authenticated"
    assert ("login.factor2.app", "failure") in orch.events and orch.successes == 1


def test_wrong_code_answer_is_the_same_for_every_kind(client, db, user, clock, orch, as_session):
    as_session(SessionState.FACTOR1_PASSED)
    answers = []
    for kind in ("totp", "backup", "totp"):
        orch.failures = 0
        answers.append(client.post(f"/api/mfa/{kind}/verify", json={"code": "12345678"}).json())
    assert answers[0] == answers[1] == answers[2]
    assert answers[0] == {"error": "not_accepted", "message": "Not accepted. 4 tries left.", "tries_left": 4}


def test_backup_code_login(client, db, user, orch, as_session):
    code = backup_codes.generate(db, user)[0]
    as_session(SessionState.FACTOR1_PASSED)
    r = client.post("/api/mfa/backup/verify", json={"code": code})
    assert r.status_code == 200 and r.json()["state"] == "authenticated"
    assert "9 backup codes left" in r.json()["message"]
    r = client.post("/api/mfa/backup/verify", json={"code": code})
    assert r.status_code == 401


def test_backup_generate_endpoint(client, user, orch, as_session):
    as_session(SessionState.AUTHENTICATED)
    r = client.post("/api/mfa/backup/generate")
    assert r.status_code == 200 and len(r.json()["codes"]) == 10


def test_email_route_refused_when_backup_codes_exist(client, db, user, orch, as_session, sent):
    backup_codes.generate(db, user)
    as_session(SessionState.FACTOR1_PASSED)
    r = client.post("/api/mfa/email/send")
    assert r.status_code == 403 and sent == []


def test_email_route_refused_when_app_exists(client, db, confirmed_app, orch, as_session, sent):
    as_session(SessionState.FACTOR1_PASSED)
    assert client.post("/api/mfa/email/send").status_code == 403


def test_email_route_reaches_only_restricted(client, db, user, clock, orch, as_session, sent):
    as_session(SessionState.FACTOR1_PASSED)
    r = client.post("/api/mfa/email/send")
    assert r.status_code == 202
    r = client.post("/api/mfa/email/verify", json={"code": emailed_code(sent)})
    assert r.status_code == 200 and r.json()["state"] == "restricted"


def test_report_app_lost(client, db, confirmed_app, clock, orch, as_session):
    as_session(SessionState.AUTHENTICATED)
    r = client.post("/api/mfa/totp/lost")
    assert r.status_code == 200
    factor = db.scalar(select(SecondFactor))
    db.refresh(factor)
    assert factor.suspended_at is not None
    assert orch.holds == [("delete_lost_factor", factor.id)]
    assert not totp.verify_code(db, confirmed_app, app_code(db, confirmed_app, clock))


def test_remove_app(client, db, confirmed_app, orch, as_session):
    as_session(SessionState.AUTHENTICATED)
    assert client.delete("/api/mfa/totp").status_code == 200
    assert db.scalar(select(SecondFactor)) is None
    assert client.delete("/api/mfa/totp").status_code == 404
