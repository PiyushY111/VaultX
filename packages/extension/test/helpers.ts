import {
  DEFAULT_KDF_PARAMS,
  deriveKeys,
  deriveMasterKey,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
} from '@password-manager/crypto';
import type { KeyValueStore } from '../src/background/storage';
import { encryptVaultItem, type VaultItemData } from '../src/background/items';
import { toBase64 } from '../src/shared/base64';

export const SERVER = 'http://127.0.0.1:3000';

/** In-memory stand-in for a chrome.storage area. */
export class MemoryStore implements KeyValueStore {
  readonly data = new Map<string, unknown>();
  async get<T>(key: string) {
    return structuredClone(this.data.get(key)) as T | undefined;
  }
  async set(key: string, value: unknown) {
    this.data.set(key, structuredClone(value));
  }
  async remove(key: string) {
    this.data.delete(key);
  }
  async clear() {
    this.data.clear();
  }
}

interface StoredItem {
  id: string;
  revision: number;
  encrypted_data: string;
  nonce: string;
}

/**
 * Minimal packages/server stand-in, exposed as a fetch implementation.
 * Records every request so tests can assert on what crosses the network.
 */
export function createFakeServer() {
  const requests: { method: string; url: string; body: string }[] = [];
  const users = new Map<string, Record<string, unknown>>();
  const items: StoredItem[] = [];
  const tokens = new Set<string>();
  let nextId = 1;

  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });

  const fetch: typeof globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    const bodyText = typeof init.body === 'string' ? init.body : '';
    requests.push({ method, url, body: bodyText });
    const body = bodyText ? JSON.parse(bodyText) : {};
    const path = url.slice(SERVER.length);
    const headers = (init.headers ?? {}) as Record<string, string>;
    const authorized = tokens.has((headers.authorization ?? '').replace(/^Bearer /, ''));
    const now = new Date().toISOString();

    if (path === '/prelogin') {
      const user = users.get(body.email);
      return json(200, {
        kdf_salt: user?.kdf_salt ?? 'AAAAAAAAAAAAAAAAAAAAAA==',
        kdf_params: user?.kdf_params ?? DEFAULT_KDF_PARAMS,
      });
    }
    if (path === '/login') {
      const user = users.get(body.email);
      if (!user || user.auth_hash !== body.auth_hash)
        return json(401, { message: 'Invalid email or auth hash' });
      const token = `token-${nextId++}`;
      tokens.add(token);
      return json(200, { token, expires_at: now });
    }
    if (!authorized) return json(401, { message: 'Unauthorized' });
    const [user] = users.values();
    if (path === '/vault-key') return json(200, user);
    if (path === '/vault-items' && method === 'GET') {
      return json(200, {
        items: items.map((item) => ({ ...item, created_at: now, updated_at: now })),
      });
    }
    if (path === '/logout' && method === 'POST') {
      tokens.delete((headers.authorization ?? '').replace(/^Bearer /, ''));
      return new Response(null, { status: 204 });
    }
    if (path === '/vault-items' && method === 'POST') {
      if (body.revision !== 1 || items.some((item) => item.id === body.id))
        return json(409, { message: 'Conflict' });
      const item = {
        id: body.id,
        revision: 1,
        encrypted_data: body.encrypted_data,
        nonce: body.nonce,
      };
      items.push(item);
      return json(201, { ...item, created_at: now, updated_at: now });
    }
    const match = /^\/vault-items\/(.+)$/.exec(path);
    const existing = match && items.find((item) => item.id === decodeURIComponent(match[1]!));
    if (existing && method === 'PUT') {
      if (body.revision !== existing.revision + 1)
        return json(409, { message: 'Changed elsewhere', current_revision: existing.revision });
      Object.assign(existing, {
        revision: body.revision,
        encrypted_data: body.encrypted_data,
        nonce: body.nonce,
      });
      return json(200, { ...existing, created_at: now, updated_at: now });
    }
    return json(404, { message: 'Not found' });
  };

  return {
    fetch,
    requests,
    items,
    tokens,
    expireSessions: () => tokens.clear(),
    /** Registers an account the way the web vault would; returns its vault key for seeding items. */
    async register(email: string, password: string): Promise<Uint8Array> {
      const salt = await generateSalt();
      const masterKey = await deriveMasterKey(password, salt, DEFAULT_KDF_PARAMS);
      const { stretchedMasterKey, authHash } = await deriveKeys(masterKey);
      const vaultKey = await generateVaultKey();
      const wrapped = await encryptVaultKey(vaultKey, stretchedMasterKey);
      users.set(email, {
        auth_hash: toBase64(authHash),
        kdf_salt: toBase64(salt),
        kdf_params: DEFAULT_KDF_PARAMS,
        encrypted_vault_key: toBase64(wrapped.ciphertext),
        vault_key_nonce: toBase64(wrapped.nonce),
      });
      return vaultKey;
    },
    async seedItem(vaultKey: Uint8Array, data: VaultItemData, revision = 1): Promise<string> {
      const payload = await encryptVaultItem(data, vaultKey, crypto.randomUUID(), revision);
      items.push(payload);
      return payload.id;
    },
  };
}
