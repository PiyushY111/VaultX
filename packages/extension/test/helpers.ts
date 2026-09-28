import {
  DEFAULT_KDF_PARAMS,
  deriveKeys,
  deriveMasterKey,
  encryptManifest,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
  nextManifest,
  type VaultManifest,
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
/** The fake's authenticator: this code is valid for accounts with two-factor on. */
export const FAKE_TOTP_CODE = '123456';

interface StoredManifest {
  version: number;
  encrypted_data: string;
  nonce: string;
}

export function createFakeServer() {
  const requests: { method: string; url: string; body: string }[] = [];
  const users = new Map<string, Record<string, unknown>>();
  const items: StoredItem[] = [];
  const state = {
    manifest: null as StoredManifest | null,
    twoFactor: false,
    recoveryCodes: [] as string[],
    /** "Require passkey" on the web vault: TOTP no longer counts. */
    passkeyOnly: false,
  };
  /** Applies a write's manifest if it's the next version, like the real server. */
  const manifestConflict = (manifest: StoredManifest | undefined) => {
    const current = state.manifest?.version ?? 0;
    if (!manifest || manifest.version !== current + 1) {
      return json(409, { message: 'Your vault was changed elsewhere.', manifest_version: current });
    }
    state.manifest = manifest;
    return null;
  };
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
      if (state.twoFactor) {
        const index = state.recoveryCodes.indexOf(body.recovery_code);
        // As the real server: the accepted methods, and passkey options (unused here).
        const details = {
          totp_required: true,
          second_factor_methods: state.passkeyOnly
            ? ['webauthn', 'recovery_code']
            : ['totp', 'recovery_code'],
          ...(state.passkeyOnly && {
            webauthn_options: { challenge: 'unused', rpId: 'localhost' },
          }),
        };
        if (!body.totp_code && !body.recovery_code) {
          return json(401, { message: 'Enter the 6-digit code.', ...details });
        }
        const totpOk = body.totp_code === FAKE_TOTP_CODE && !state.passkeyOnly;
        if (!totpOk && index === -1) {
          return json(401, { message: 'That two-factor code is incorrect.', ...details });
        }
        if (index !== -1) state.recoveryCodes.splice(index, 1);
      }
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
        manifest: state.manifest,
      });
    }
    if (path === '/vault-manifest' && method === 'PUT') {
      return manifestConflict(body) ?? new Response(null, { status: 204 });
    }
    if (path === '/logout' && method === 'POST') {
      tokens.delete((headers.authorization ?? '').replace(/^Bearer /, ''));
      return new Response(null, { status: 204 });
    }
    if (path === '/vault-items' && method === 'POST') {
      if (body.revision !== 1 || items.some((item) => item.id === body.id))
        return json(409, { message: 'Conflict' });
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
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
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
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
    state,
    expireSessions: () => tokens.clear(),
    enableTwoFactor(recoveryCodes: string[] = ['RECOV-ERY01']) {
      state.twoFactor = true;
      state.recoveryCodes = [...recoveryCodes];
    },
    /** An account whose second factor must be a passkey (or a recovery code). */
    requirePasskey(recoveryCodes: string[] = ['RECOV-ERY01']) {
      state.twoFactor = true;
      state.passkeyOnly = true;
      state.recoveryCodes = [...recoveryCodes];
    },
    /** Registers an account the way the web vault would; returns its vault key for seeding items. */
    /**
     * The vault's manifest as its owner last wrote it, in plaintext, so
     * seeded items can be added to it as the web vault would.
     */
    plainManifest: null as VaultManifest | null,
    async writeManifest(vaultKey: Uint8Array, manifest: VaultManifest) {
      const { ciphertext, nonce } = await encryptManifest(manifest, vaultKey);
      state.manifest = {
        version: manifest.version,
        encrypted_data: toBase64(ciphertext),
        nonce: toBase64(nonce),
      };
      this.plainManifest = manifest;
    },
    /** A vault from before manifests existed: items, no manifest. */
    makeLegacy() {
      state.manifest = null;
      this.plainManifest = null;
    },
    /** Registers like the web vault: the account, then its first (empty) manifest. */
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
      await this.writeManifest(vaultKey, nextManifest(null, {}, 'web'));
      return vaultKey;
    },
    /** An item the server adds on its own: not in the owner's manifest. */
    async plantItem(vaultKey: Uint8Array, data: VaultItemData): Promise<string> {
      const payload = await encryptVaultItem(data, vaultKey, crypto.randomUUID(), 1);
      items.push(payload);
      return payload.id;
    },
    /** Saves an item as the web vault would, moving the manifest on (unless the vault is legacy). */
    async seedItem(vaultKey: Uint8Array, data: VaultItemData, revision = 1): Promise<string> {
      const payload = await encryptVaultItem(data, vaultKey, crypto.randomUUID(), revision);
      items.push(payload);
      if (this.plainManifest) {
        await this.writeManifest(
          vaultKey,
          nextManifest(this.plainManifest, { set: [{ id: payload.id, revision }] }, 'web'),
        );
      }
      return payload.id;
    },
  };
}
