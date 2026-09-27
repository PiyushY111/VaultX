import type { KdfParams } from '@password-manager/crypto';

// Same endpoints and payloads as packages/web/src/api.ts. Kept separate for
// now because the extension talks to a user-configured server URL; a shared
// client package would remove the duplication.

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

export interface EncryptedItemPayload {
  encrypted_data: string;
  nonce: string;
}

export interface ItemResponse extends EncryptedItemPayload {
  id: string;
  created_at: string;
  updated_at: string;
}

export interface VaultKeyResponse {
  encrypted_vault_key: string;
  vault_key_nonce: string;
  kdf_salt: string;
  kdf_params: KdfParams;
}

export type Api = ReturnType<typeof createApi>;

export function createApi(baseUrl: string, fetchImpl: typeof fetch) {
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
      response = await fetchImpl(`${baseUrl}${path}`, init);
    } catch {
      throw new ApiError(0, `Could not reach the server at ${baseUrl}`);
    }
    if (response.status === 204) return undefined as T;
    const data = (await response.json().catch(() => null)) as { message?: string } | null;
    if (!response.ok)
      throw new ApiError(response.status, data?.message ?? response.statusText, data ?? {});
    return data as T;
  }

  return {
    prelogin: (email: string) =>
      request<{ kdf_salt: string; kdf_params: KdfParams }>('POST', '/prelogin', {
        body: { email },
      }),
    login: (email: string, authHash: string) =>
      request<{ token: string; expires_at: string }>('POST', '/login', {
        body: { email, auth_hash: authHash },
      }),
    getVaultKey: (token: string) => request<VaultKeyResponse>('GET', '/vault-key', { token }),
    listItems: (token: string) =>
      request<{ items: ItemResponse[] }>('GET', '/vault-items', { token }),
    createItem: (token: string, body: EncryptedItemPayload) =>
      request<ItemResponse>('POST', '/vault-items', { token, body }),
    updateItem: (token: string, id: string, body: EncryptedItemPayload) =>
      request<ItemResponse>('PUT', `/vault-items/${encodeURIComponent(id)}`, { token, body }),
  };
}
