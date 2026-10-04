# Test plan

From §10 of the design. A row changes from **Planned** to **Verified** only when it has passed on the
implementation, and the "Where" column then points at the test or the recorded result.

## Security tests (owner: M5, with each slice owner)

| ID | Test | Slices | Where | Status |
|---|---|---|---|---|
| ST1 | Correct password + correct app code; correct password + passkey | M1, M2, M3, M5 | `tests/security/test_attacks.py::test_st01_*` | Planned |
| ST2 | Wrong password five times, then a sixth | M1, M5 | `test_st02_*` | Planned |
| ST3 | Wrong app code, then the correct one | M2, M5 | `test_st03_*` | Planned |
| ST4 | Same app code twice; same backup code twice | M2 | `test_st04_*` | Planned |
| ST5 | Same signed passkey answer twice; two copies at the same instant | M3, M5 | `test_st05_*` | Planned |
| ST6 | Challenge from session A answered from session B; recovery code typed at login | M5, M2 | `test_st06_*` | Planned |
| ST7 | Set-up challenge used at login while both sessions are open | M5 | `test_st07_*` | Planned |
| ST8 | Signed-in page after Factor 1 only; second-factor request without Factor 1 | M5 | `test_st08_*` | Planned |
| ST9 | Session expiry, logout, a session ID planted before login | M1, M5 | `test_st09_*` | Planned |
| ST10 | Proxy with an untrusted certificate; `http://`; passkey from a look-alike origin | M5, M3 | manual, recorded here | Planned |
| ST11 | Forgotten password; lost device with backup code; emailed-code route | M5, M2 | `test_st11_*` | Planned |

## Accessibility tests (owner: M4)

| ID | Test | Where | Status |
|---|---|---|---|
| AT1 | Register, set up, log in and recover with NVDA and the monitor off | manual, recorded here | Planned |
| AT2 | The same flows with the keyboard only | manual, recorded here | Planned |
| AT3 | VoiceOver (macOS, iOS), TalkBack; braille display with speech muted; voice control | manual, recorded here | Planned |
| AT4 | Every error message: wrong code, expired code, lockout, cancelled passkey prompt | manual + automated | Planned |
| AT5 | Passkey and OTP set-up and login without a QR code; paste and autofill; device PIN | manual, recorded here | Planned |
| AT6 | Automated scan (axe / Lighthouse); zoom 200 % and 400 %; high-contrast theme | report attached here | Planned |
