# How we work without clashing

The previous repository failed because people edited the same files and built against different ideas of the
design. These rules prevent both.

## 1. You edit only the files you own

Ownership is in the README team table and enforced by `.github/CODEOWNERS`, so GitHub asks the owner to review any
pull request that touches their files.

**If you need something changed in someone else's file, ask them (an issue or the group chat). Do not change it
yourself.** That includes "just a one-line fix".

## 2. Shared contract files change only with agreement

These files are what everyone builds against. They were written from the design before any slice was built:

| File | What it fixes |
|---|---|
| `backend/app/models.py` | Every database table and column |
| `backend/app/schemas/common.py` | Session states, next-step values, the response format |
| `backend/app/core/policy.py` | Every number in the design |
| `backend/app/core/errors.py` | The error format |
| `backend/app/core/config.py`, `core/db.py`, `main.py` | Settings, database, app wiring |
| `backend/tests/conftest.py`, `tests/test_contract.py` | Shared test set-up and contract checks |
| `backend/requirements.txt` | Python packages |
| `docs/api-contract.md` | Endpoints and cross-slice functions |

To change one, open a pull request that touches **only** that file, say why in the description, and get approval
from every member whose slice uses it. If it changes something in the design, also update
`docs/implementation-assumptions.md` so the report can say so.

## 3. Build against the contract, not against each other's code

Every function another member calls already exists with its final name, arguments and docstring. Until its owner
builds it, it raises a "not built yet" error. **Do not rename or change the arguments of a function listed in
`docs/api-contract.md` §3.** Other people are already calling it.

To test your slice before a function you call is built, replace it in your test:

```python
def test_login_accepts_correct_password(client, monkeypatch):
    monkeypatch.setattr("app.accounts.router.check_lockout", lambda db, user_id, ip: None)
    ...

# or, for a FastAPI dependency such as require_state(...):
app.dependency_overrides[some_dependency] = lambda: fake_session
```

M4 builds the client against `docs/api-contract.md` and the live `/docs` page. A mock mode in `js/api.js` is fine
until the endpoints are built.

## 4. Build order

Everything else depends on these, so they come first:

1. **M5**: `require_state`, `require_recent_factor2`, `require_can_add_factor`, `complete_factor1/2`,
   `issue_challenge`/`consume_challenge`, `audit`, `check_lockout`/`record_failure`/`record_success`
2. **M1**: `sessions.py` (`create_session`, `load_session`, `rotate_session_id`), then `crypto.py`
3. **M2**: `mailer.send_email` in console mode (M1 and M5 need it to send codes)

After that, every slice can proceed in parallel. The integration checkpoint is a full register → set up → log in
→ recover run with NVDA and the monitor off (§10.2 AT1).

## 5. Branches and pull requests

- `main` always runs and its tests always pass. Nobody pushes to `main` directly.
- Branch from the latest `main` for each piece of work, prefixed with your member number:
  `m1/login-endpoint`, `m4/register-screen`. Keep branches short: open a pull request within a few days.
- Before opening a pull request, update your branch and run the tests:
  ```bash
  git fetch origin && git merge origin/main
  cd backend && pytest
  ```
- Each pull request needs one approval and passing CI. GitHub requests the code owner automatically.
- Commit messages: short, present tense, prefixed: `m2: add TOTP replay guard`.

## 6. Coding rules that come from the design

- Every message a user can receive is a full sentence that says what happened and what to do next (AR-5).
  Raise `AppError`, never a bare `HTTPException`.
- Wrong password, PIN or code: always the same wording, and never reveal whether a username exists (SR-8).
- Never decide or change a session's state yourself. Use M5's functions (D6, SR-2).
- Times: use `utc_now()` from `app.core.db`, never `datetime.now()` or `datetime.utcnow()`.
- Numbers from the design come from `app.core.policy`. Never hard-code them.
- Call `audit()` for every login, set-up, failure, lockout and recovery event (FR8).
- Never write cryptography yourself. Use the libraries in `requirements.txt` (§3.1).
- Never commit `.env`, keys, certificates or database files. `.gitignore` already excludes them.

## 7. Tests and the report

Each member writes unit tests for their slice in `backend/tests/test_<mN>_*.py`. Security tests ST1–ST11 go in
`backend/tests/security/` (M5), and accessibility test results go in `docs/test-plan.md` (M4). A test in the
design's §10 changes from "Planned" to "Verified" only when it has passed on the implementation.
