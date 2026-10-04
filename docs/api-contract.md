# API contract

This expands Appendix B of the design. Every endpoint below already exists in the code with this path, required
state and body shape. Changing any of it requires the agreement described in CONTRIBUTING.md §2.
`backend/tests/test_contract.py` fails if an endpoint disappears.

## 1. Conventions

- All endpoints are under `/api` and served from the same origin as the client (IA-1).
- **Every response** is an `AuthResponse` (or extends one): `{ "state", "next", "message" }`.
  - `state`: one of `anonymous`, `factor1_passed`, `restricted`, `authenticated`, `locked`, `locked_until_recovery` (Fig. 3)
  - `next`: the screen to show next (§7.8): `register`, `choose_factor`, `setup`, `backup_codes`, `login_step1`,
    `login_step2`, `signed_in`, `manage_factors`, `recovery`
  - `message`: a full sentence the client shows and announces (AR-4, AR-5)
- **Every error** is `{ "error", "message", ["state"], ["next"], ["tries_left"], ["retry_after_seconds"], ["fields"] }`.
  Wrong password, PIN or code always gives `error: "not_accepted"` with the same message (SR-8).
- Codes are sent as `{ "code": "..." }`. Spaces and hyphens are allowed and stripped by the server (§7.6).
- Session: `cryptix_session` cookie, httpOnly, Secure, SameSite=Strict. Every POST/PUT/PATCH/DELETE sends the
  `X-CSRF-Token` header with the value from `/api/auth/status` (§6.6).

## 2. Endpoints

"Requires" is the FastAPI dependency from `orchestrator/state.py` that guards the endpoint (SR-2):
- **F1** = `require_state(factor1_passed)` (login step 2)
- **CanAdd** = `require_can_add_factor()`
- **Recent** = `require_recent_factor2()` (SR-9)

### M1: Accounts and Factor 1

| Method | Path | Requires | Body | Success |
|---|---|---|---|---|
| POST | `/register` | none | `{ username, email, secret, secret_kind: "password"\|"pin" }` | 201, state `restricted`, next `choose_factor` |
| POST | `/email/verify` | restricted or authenticated | `{ code }` | 200 |
| POST | `/email/resend` | restricted or authenticated | none | 202 |
| POST | `/login` | none | `{ username, secret }` | 200, state `factor1_passed`, next `login_step2` |
| POST | `/logout` | none | none | 200, state `anonymous`, next `login_step1` |

### M2: Authenticator app, emailed codes, backup codes

| Method | Path | Requires | Body | Success |
|---|---|---|---|---|
| POST | `/mfa/totp/enroll` | CanAdd | none | 200 + `{ otpauth_uri, secret_grouped }` |
| POST | `/mfa/totp/confirm` | CanAdd | `{ code }` | 200, next `backup_codes` |
| POST | `/mfa/totp/verify` | F1 | `{ code }` | 200, state `authenticated`, next `signed_in` |
| POST | `/mfa/totp/lost` | authenticated or restricted | none | 200 |
| DELETE | `/mfa/totp` | Recent | none | 200 |
| POST | `/mfa/email/send` | F1 | none | 202 |
| POST | `/mfa/email/verify` | F1 | `{ code }` | 200, state `restricted` (never `authenticated`) |
| POST | `/mfa/backup/generate` | Recent | none | 200 + `{ codes: [...] }`, shown once |
| POST | `/mfa/backup/verify` | F1 | `{ code }` | 200, state `authenticated` |

### M3: Passkeys and remembered browser

| Method | Path | Requires | Body | Success |
|---|---|---|---|---|
| POST | `/webauthn/register/options` | CanAdd | none | 200 + `{ options }` |
| POST | `/webauthn/register/verify` | CanAdd | `{ credential, label? }` | 200, next `backup_codes` |
| POST | `/webauthn/login/options` | F1 | none | 200 + `{ options }` |
| POST | `/webauthn/login/verify` | F1 | `{ credential }` | 200, state `authenticated` |
| GET | `/webauthn/credentials` | authenticated | none | 200 + `{ credentials: [{ id, label, created_at, suspended }] }` |
| POST | `/webauthn/credentials/{id}/lost` | authenticated or restricted | none | 200 |
| DELETE | `/webauthn/credentials/{id}` | Recent | none | 200 |
| POST | `/device/remember` | Recent | none | 200 |
| POST | `/device/verify` | F1 | none (cookie) | 200, state `authenticated` |
| DELETE | `/device` | authenticated | none | 200 |

### M5: Orchestration and recovery

| Method | Path | Requires | Body | Success |
|---|---|---|---|---|
| GET | `/auth/status` | none | none | 200 + `{ username, csrf_token, second_factor_options, idle_seconds_left }` |
| POST | `/recovery/start` | none | `{ username }` | 202, same answer whether or not the user exists (SR-8) |
| POST | `/recovery/verify` | none | `{ username, code, new_secret, secret_kind }` | 200, every session ended |
| GET | `/mfa/cancel/{token}` | none | none | 200 |
| POST | `/mfa/restricted/hold` | restricted | none | 200 |

## 3. Functions members call across slices

These are the seams between slices. Names and arguments are fixed. Each one exists now and raises
"not built yet" until its owner builds it.

| Function | File | Owner | Called by |
|---|---|---|---|
| `require_state(*states)`, `require_recent_factor2()`, `require_can_add_factor()` | `orchestrator/state.py` | M5 | M1, M2, M3 routers |
| `complete_factor1`, `complete_factor2`, `complete_remembered_browser`, `enter_restricted` | `orchestrator/state.py` | M5 | M1, M2, M3 |
| `issue_challenge`, `consume_challenge`, `ChallengePurpose` | `orchestrator/challenges.py` | M5 | M2, M3 |
| `check_lockout`, `record_failure`, `record_success` | `orchestrator/lockout.py` | M5 | M1, M2, M3 |
| `audit` | `orchestrator/audit.py` | M5 | everyone |
| `start_hold`, `hold_is_over`, `cancel_hold` | `orchestrator/holds.py` | M5 | M2, M3 |
| `create_session`, `load_session`, `rotate_session_id`, `end_session`, `end_all_sessions` | `accounts/sessions.py` | M1 | M5 |
| `validate_new_secret`, `hash_secret`, `verify_secret` | `accounts/passwords.py` | M1 | M5 (recovery) |
| `encrypt_for_user`, `decrypt_for_user`, `keyed_hash` | `core/crypto.py` | M1 | M2 |
| `send_email` | `otp/mailer.py` | M2 | M1, M5 |
| `issue_email_code`, `verify_email_code`, `EmailPurpose` | `otp/email_codes.py` | M2 | M1, M5 |
| `remaining` (backup codes left) | `otp/backup_codes.py` | M2 | M5 (status) |
| `createPasskey(options)`, `usePasskey(options)` | `frontend/js/webauthn.js` | M3 | M4 |
| `NEXT_STEP_PAGES` | `frontend/js/api.js` | M4 | must match `NextStep` |

## 4. Open items to agree as a group

- `GET /mfa/cancel/{token}` is opened from an email link, so it should show a page rather than JSON, and a GET
  should not change anything. Suggested approach: the link opens a client page that POSTs the token (M5 and M4).
- The Manage factors screen needs the number of backup codes left and whether an app is set up. Suggested
  approach: add both to `/auth/status` when the state is `authenticated` (M5, M2 and M4).
