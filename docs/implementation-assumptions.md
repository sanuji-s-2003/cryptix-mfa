# Implementation assumptions

The brief requires every assumption to be stated. The design's own assumptions are A1–A9 (§1.7). These are the
extra ones the implementation makes where the design is silent. Add a row whenever you make a new one, and give
the reason.

| ID | Assumption | Why | Owner |
|---|---|---|---|
| IA-1 | The server that runs the API also serves the client, and the API lives under `/api`. | One origin keeps the session cookie `SameSite=Strict` (§6.6) and makes the passkey origin the page's own origin (§6.3 C4), with no cross-origin set-up. | Group |
| IA-2 | Tables are created at start-up from `models.py`, with no migration tool. | One server and one database at coursework scale (A4). | Group |
| IA-3 | Local development and unit tests may use SQLite. CI, the integration checkpoint and the demo use PostgreSQL as designed (§3.1). | Lets every member run the project without installing a database server. | Group |
| IA-4 | Columns and tables added beyond Fig. 8 and 9 (marked `+` in `models.py`): user id and timestamps on sessions, CSRF token, `factor2_at`; `secret_kind` and `email_lookup_hash` on users; passkey credential ID, sign count and transports; `confirmed_at` and `label` on second factors; and the `email_codes`, `remembered_browsers`, `lockout_counters` and `pending_changes` tables. | Each is required by a rule the design states (SR-7, SR-9, §4.3, §5.3, §5.4, §6.6, Appendix A) or by the WebAuthn standard, but the figures do not draw them. | Group |
| IA-5 | In development, emails are printed to the server log instead of being sent (`EMAIL_MODE=console`). | No mail account is needed to develop or demonstrate. Real sending is available with `EMAIL_MODE=smtp`. | M2 |
| IA-6 | An emailed code expires 10 minutes after it is sent. Sending a new code for the same purpose cancels the previous one. | The design fixes the length (8 digits) and the retention (§8.5) but not the lifetime. Ten minutes leaves time to switch to the mail app with a screen reader; one live code per purpose keeps the guessing space at one code. | M2 |
| IA-7 | During development the site runs on `http://localhost`; the demo runs over HTTPS with a locally trusted certificate (A3). | Browsers treat localhost as a secure context, so passkeys work. Chrome refuses passkeys on a page with a certificate warning. | M5 |
| IA-8 | Backup codes and emailed codes are hashed with Argon2id at the OWASP minimum cost (19 MiB, 2 passes). | SR-5 asks for salted hashes. A 20-digit backup code carries 66 bits and an emailed code lives 10 minutes, so a higher cost buys nothing, while a backup-code login checks up to ten hashes. | M2 |
| IA-9 | App, backup and emailed codes are not tied to a session challenge. Their single use comes from the code itself: the last accepted time step for app codes, `used_at` for backup and emailed codes, each claimed in one conditional `UPDATE`. | §6.2 names these as the replay defences for codes. A challenge consumed before the check would send a user who mistypes back to request a new one, which ST3 rules out. | M2 |
| IA-10 | A user has at most one working authenticator app. Starting a new set-up replaces an unconfirmed one; a confirmed one must be removed (or reported lost) first. | §4.3 speaks of "the" app; one app keeps Manage factors simple to read aloud. | M2 |
| IA-11 | Confirming the app with its first correct code counts as proving Factor 2 (`complete_factor2`), and the next step is the backup-codes screen. | Fig. 4 ends set-up with "new session ID, Authenticated", and `/mfa/backup/generate` needs a recent Factor 2 (SR-9). | M2 |
| IA-12 | An address that is not confirmed is used only to send its confirmation code. A login or recovery code for it is silently not sent, and the caller answers as if it had been. | Fig. 4: until confirmed, the address is not used for recovery. Answering the same way keeps SR-8. | M2 |
