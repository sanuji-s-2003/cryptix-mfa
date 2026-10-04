"""Every number the design fixes, in one place.  [SHARED contract file]

Change a value only if the design document changes too. Section numbers refer to
docs/design/Cryptix-Unified-Design_Submission_02.pdf.
"""

# Factor 1 (§4.2)
PASSWORD_MIN_LENGTH = 8
PIN_MIN_DIGITS = 6

# Authenticator app (§4.3, RFC 6238)
TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
TOTP_VALID_WINDOW = 1  # ±1 step: "three valid app codes at any moment" (§5.3)

# Emailed codes (§1.6)
EMAIL_CODE_DIGITS = 8
EMAIL_CODE_TTL_MINUTES = 10  # not fixed by the design: see docs/implementation-assumptions.md IA-6

# Backup codes (§4.3, §7.3)
BACKUP_CODE_COUNT = 10
BACKUP_CODE_DIGITS = 20
BACKUP_CODE_GROUP = 4

# Challenges (§5.2, §6.2)
CHALLENGE_TTL_SECONDS = 120

# Sessions (SR-7, SR-9, §4.7)
SESSION_IDLE_MINUTES = 30
SESSION_ABSOLUTE_HOURS = 12
SESSION_WARNING_MINUTES = 2
REAUTH_WINDOW_MINUTES = 5

# Lockout (§5.3, SR-6)
LOCK_AFTER_CONSECUTIVE = 5
LOCK_FIRST_MINUTES = 1
LOCK_MAX_MINUTES = 15
HARD_LOCK_TOTAL = 100
IP_FAILURE_LIMIT = 20
IP_WINDOW_MINUTES = 15

# Recovery and waiting periods (§5.4, SR-10)
RESTRICTED_HOLD_HOURS = 24
LOST_FACTOR_DELETE_HOURS = 24

# Remembered browser (§4.6)
REMEMBER_BROWSER_DAYS = 30

# Retention (§8.5)
EMAIL_CODE_RETAIN_HOURS_AFTER_EXPIRY = 1
AUDIT_RETENTION_DAYS = 90
