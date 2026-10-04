// Browser side of the passkey ceremonies (§4.3, §8.3).  Owner: M3
// M4's pages call these two functions and never use navigator.credentials directly.
// Before calling, the page says "Registering a security key for Cryptix" (§7.6).

// options: the `options` field of /api/webauthn/register/options. Returns the credential as JSON.
export async function createPasskey(options) {
  throw new Error('createPasskey() not built yet. Owner: M3');
}

// options: the `options` field of /api/webauthn/login/options. Returns the assertion as JSON.
export async function usePasskey(options) {
  throw new Error('usePasskey() not built yet. Owner: M3');
}
