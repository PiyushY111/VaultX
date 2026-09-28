import type { KdfParams } from '@password-manager/crypto';

/**
 * Thin HTTP client for the server API. Everything it sends is either public
 * (email, KDF salt/params), an auth hash, or ciphertext produced by
 * src/vault — it never receives a master password, key, or plaintext item.
 */

const API_BASE = '/api';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** Other fields of the JSON error body, e.g. attempts_remaining. */
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * User-facing message for a failed /login: attempts left before the
 * per-account lockout, or how long to wait once locked.
 */
export function describeLoginFailure(error: ApiError): string {
  const { attempts_remaining: remaining, retry_after_seconds: retryAfter } = error.details;
  // The password was right; the server's message is about the code.
  if (needsSecondFactor(error)) return error.message;
  if (error.status === 429) {
    if (typeof retryAfter !== 'number') return error.message; // Per-IP rate limit.
    const minutes = Math.max(1, Math.ceil(retryAfter / 60));
    return `Too many failed attempts for this account. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
  }
  const base = 'Incorrect email or master password.';
  if (typeof remaining !== 'number') return base;
  if (remaining > 0) {
    return `${base} ${remaining} attempt${remaining === 1 ? '' : 's'} left before this account is temporarily locked.`;
  }
  return `${base} This account is now temporarily locked after too many failed attempts.`;
}

/** The password was right, and the account needs a two-factor code too. */
export const needsSecondFactor = (error: unknown): boolean =>
  error instanceof ApiError && error.details.totp_required === true;

/** A second factor: a code from the authenticator app, or a recovery code. */
export type SecondFactor = { totp_code: string } | { recovery_code: string };

export interface SignupRequest {
  email: string;
  auth_hash: string;
  encrypted_vault_key: string;
  vault_key_nonce: string;
  kdf_salt: string;
  kdf_params: KdfParams;
}

export interface PreloginResponse {
  kdf_salt: string;
  kdf_params: KdfParams;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
}

export interface VaultKeyResponse {
  encrypted_vault_key: string;
  vault_key_nonce: string;
  kdf_salt: string;
  kdf_params: KdfParams;
}

export interface EncryptedItemPayload {
  encrypted_data: string;
  nonce: string;
}

/** A save of one item: its id and revision are bound into the ciphertext. */
export interface ItemRevisionPayload extends EncryptedItemPayload {
  id: string;
  revision: number;
}

/** The encrypted vault manifest at one version (see @password-manager/crypto). */
export interface ManifestPayload extends EncryptedItemPayload {
  version: number;
}

export interface VaultResponse {
  items: ItemResponse[];
  manifest: ManifestPayload | null;
}

export interface AccountInfo {
  email: string;
  created_at: string;
  totp_enabled: boolean;
  recovery_codes_remaining: number;
}

/** Re-authentication for sensitive account changes. */
export type Reauth = { current_auth_hash: string } & Partial<{
  totp_code: string;
  recovery_code: string;
}>;

export interface ItemResponse extends EncryptedItemPayload {
  id: string;
  revision: number;
  created_at: string;
  updated_at: string;
}

export interface SessionInfo {
  id: string;
  client: 'web' | 'extension' | null;
  user_agent: string | null;
  created_at: string;
  last_used_at: string;
  expires_at: string;
  current: boolean;
}

export interface ChangePasswordRequest {
  current_auth_hash: string;
  auth_hash: string;
  kdf_salt: string;
  kdf_params: KdfParams;
  encrypted_vault_key: string;
  vault_key_nonce: string;
  items: ItemRevisionPayload[];
  manifest: ManifestPayload;
}

async function request<T>(
  method: string,
  path: string,
  options: { body?: unknown; token?: string } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  const init: RequestInit = { method, headers, credentials: 'omit', cache: 'no-store' };
  if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  if (options.token) headers.authorization = `Bearer ${options.token}`;

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(0, 'Could not reach the server');
  }
  if (response.status === 204) return undefined as T;
  const data = (await response.json().catch(() => null)) as { message?: string } | null;
  if (!response.ok)
    throw new ApiError(response.status, data?.message ?? response.statusText, data ?? {});
  return data as T;
}

export const api = {
  signup: (body: SignupRequest) => request<{ id: string }>('POST', '/signup', { body }),
  prelogin: (email: string) => request<PreloginResponse>('POST', '/prelogin', { body: { email } }),
  login: (email: string, authHash: string, factor?: SecondFactor) =>
    request<LoginResponse>('POST', '/login', {
      body: { email, auth_hash: authHash, client: 'web', ...factor },
    }),
  logout: (token: string) => request<void>('POST', '/logout', { token }),
  getVaultKey: (token: string) => request<VaultKeyResponse>('GET', '/vault-key', { token }),
  listItems: (token: string) => request<VaultResponse>('GET', '/vault-items', { token }),
  // Every write carries the vault's next manifest; the server applies both or neither.
  createItem: (token: string, item: ItemRevisionPayload, manifest: ManifestPayload) =>
    request<ItemResponse>('POST', '/vault-items', { token, body: { ...item, manifest } }),
  updateItem: (token: string, { id, ...item }: ItemRevisionPayload, manifest: ManifestPayload) =>
    request<ItemResponse>('PUT', `/vault-items/${encodeURIComponent(id)}`, {
      token,
      body: { ...item, manifest },
    }),
  deleteItem: (token: string, id: string, manifest: ManifestPayload) =>
    request<void>('DELETE', `/vault-items/${encodeURIComponent(id)}`, {
      token,
      body: { manifest },
    }),
  putManifest: (token: string, manifest: ManifestPayload) =>
    request<void>('PUT', '/vault-manifest', { token, body: manifest }),
  getAccount: (token: string) => request<AccountInfo>('GET', '/account', { token }),
  setupTotp: (token: string) =>
    request<{ secret: string; otpauth_uri: string }>('POST', '/account/totp/setup', { token }),
  enableTotp: (token: string, body: { current_auth_hash: string; totp_code: string }) =>
    request<{ recovery_codes: string[] }>('POST', '/account/totp/enable', { token, body }),
  disableTotp: (token: string, body: Reauth) =>
    request<void>('POST', '/account/totp/disable', { token, body }),
  regenerateRecoveryCodes: (token: string, body: Reauth) =>
    request<{ recovery_codes: string[] }>('POST', '/account/totp/recovery-codes', {
      token,
      body,
    }),
  deleteAccount: (token: string, body: Reauth) =>
    request<void>('DELETE', '/account', { token, body }),
  listSessions: (token: string) =>
    request<{ sessions: SessionInfo[] }>('GET', '/sessions', { token }),
  revokeSession: (token: string, id: string) =>
    request<void>('DELETE', `/sessions/${encodeURIComponent(id)}`, { token }),
  revokeAllSessions: (token: string) => request<void>('DELETE', '/sessions', { token }),
  changePassword: (token: string, body: ChangePasswordRequest) =>
    request<{ items: ItemResponse[] }>('POST', '/account/password', { token, body }),
};
