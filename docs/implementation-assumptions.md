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
| IA-6 | An emailed code expires 10 minutes after it is sent. | The design fixes the length (8 digits) and the retention (§8.5) but not the lifetime. M2 to confirm. | M2 |
| IA-7 | During development the site runs on `http://localhost`; the demo runs over HTTPS with a locally trusted certificate (A3). | Browsers treat localhost as a secure context, so passkeys work. Chrome refuses passkeys on a page with a certificate warning. | M5 |
