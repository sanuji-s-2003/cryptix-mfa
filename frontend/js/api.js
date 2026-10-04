// Talks to the server.  Owner: M4
// Every response carries { state, next, message } (Appendix B; backend/app/schemas/common.py).

// NextStep value -> page. Must match NextStep in backend/app/schemas/common.py.
export const NEXT_STEP_PAGES = {
  register: 'register.html',
  choose_factor: 'choose-factor.html',
  setup: 'setup.html',
  backup_codes: 'backup-codes.html',
  login_step1: 'login.html',
  login_step2: 'login-step2.html',
  signed_in: 'signed-in.html',
  manage_factors: 'manage-factors.html',
  recovery: 'recovery.html',
};

// TODO M4: fetch('/api' + path) with JSON, credentials 'same-origin', and the
// X-CSRF-Token header from /auth/status on every change (§6.6).
export async function api(method, path, body) {
  throw new Error('api() not built yet. Owner: M4');
}
