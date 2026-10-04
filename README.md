# Cryptix: Accessible MFA for Visually Impaired Users

Group project for CS-3053 Computer Security (Semester 5). This repository implements the design in
[docs/design/Cryptix-Unified-Design_Submission_02.pdf](docs/design/Cryptix-Unified-Design_Submission_02.pdf).
**The design document is the specification.** Where the code needs something the design does not say, it is
recorded in [docs/implementation-assumptions.md](docs/implementation-assumptions.md).

A normal login is two steps: a password or PIN (something you know), then a passkey / security key or an
authenticator-app code (something you have). Every screen works with a screen reader, a keyboard and audio,
and nothing depends on sight.

## Team

| | Student ID | Name | Part of the system | Owns |
|---|---|---|---|---|
| M1 | 230135A | Dewdunika D.R.K.W.M.V.V | Accounts and Factor 1 | `backend/app/accounts/`, `backend/app/core/crypto.py` |
| M2 | 230279R | Jayasinghe E.A.T.D | Factor 2: app codes, emailed codes, backup codes | `backend/app/otp/` |
| M3 | 230384J | Madhubhashini M.D.D. | Factor 2: passkeys, remembered browser | `backend/app/passkeys/`, `frontend/js/webauthn.js` |
| M4 | 230562E | Samarakoon S.M.S.G. | Accessible client | `frontend/` (except `js/webauthn.js`) |
| M5 | 230684E | Wansandi M.G.J. | Orchestration, lockout, audit, security evaluation | `backend/app/orchestrator/`, `backend/tests/security/` |

**Each member edits only the files they own.** The full rules are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Stack (design §3.1, D1)

- Python and FastAPI, with PostgreSQL in the demo and SQLite for quick local development
- A plain HTML and JavaScript client with no framework, served by the same server
- Cryptography from established libraries only: `argon2-cffi`, `pyotp`, `webauthn`, `cryptography`

## Repository layout

```
backend/
  app/
    main.py              SHARED  registers every router and the middleware; nobody needs to edit it
    models.py            SHARED  database tables (Fig. 8 and 9)
    core/config.py       SHARED  settings from backend/.env
    core/db.py           SHARED  database engine, utc_now()
    core/errors.py       SHARED  AppError: the one error format
    core/policy.py       SHARED  every number the design fixes (lockout, expiry times, code lengths)
    schemas/common.py    SHARED  SessionState, NextStep, AuthResponse, CodeRequest
    core/crypto.py       M1
    accounts/            M1      /register /email/* /login /logout, passwords, sessions
    otp/                 M2      /mfa/totp/* /mfa/email/* /mfa/backup/*, mailer
    passkeys/            M3      /webauthn/* /device/*
    orchestrator/        M5      /auth/status /recovery/* /mfa/cancel /mfa/restricted/hold,
                                 state machine, challenges, lockout, audit, holds, middleware
  tests/
    conftest.py, test_contract.py   SHARED
    test_m1_accounts.py ...         one file per member
    security/                       M5  (ST1–ST11)
frontend/                M4      one HTML page per screen (§7.8); js/webauthn.js is M3's
docs/
  design/                the submitted unified design (PDF)
  api-contract.md        every endpoint, the state it requires, and the functions members call across slices
  test-plan.md           ST1–ST11 and AT1–AT6, with owners
  implementation-assumptions.md
```

## Running it

Requires Python 3.11 or later.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                 # then fill in DATA_KEY and HMAC_KEY (instructions inside)
uvicorn app.main:app --reload
```

- Client: http://localhost:8000
- Interactive API docs (try every endpoint): http://localhost:8000/docs
- Tests: `pytest` (run from `backend/`)

Every endpoint already exists. Until its owner builds it, it answers
`{"error": "not_implemented", "message": "This step has not been built yet. Owner: Mx."}`.

**PostgreSQL** (the design's database, needed for the integration checkpoint and the demo): run `docker compose up -d`
from the repo root and switch `DATABASE_URL` in `backend/.env` to the PostgreSQL line.

**HTTPS** (SR-1, A3): browsers treat `http://localhost` as secure, so passkeys work during development without a
certificate. For the demo, M5 sets `FORCE_HTTPS=true` and runs uvicorn with a locally trusted certificate
(for example from `mkcert`). Chrome refuses passkeys on a page with a certificate warning, so a plain self-signed
certificate is not enough.
