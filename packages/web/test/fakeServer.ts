import { vi } from 'vitest';

/**
 * In-memory stand-in for packages/server that records every request the app
 * makes, so tests can assert on exactly what crosses the network. It enforces
 * the same item-revision and session rules as the real server.
 */
export interface RecordedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

interface StoredManifest {
  version: number;
  encrypted_data: string;
  nonce: string;
}

interface StoredUser {
  email: string;
  authHash: string;
  encryptedVaultKey: string;
  vaultKeyNonce: string;
  kdfSalt: string;
  kdfParams: unknown;
  manifest: StoredManifest | null;
  totpEnabled: boolean;
  recoveryCodes: string[];
}

/** The fake's authenticator: this code is always valid when two-factor is on. */
export const FAKE_TOTP_CODE = '123456';
export const FAKE_TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

export interface StoredItem {
  id: string;
  owner: string;
  revision: number;
  encrypted_data: string;
  nonce: string;
  created_at: string;
  updated_at: string;
}

interface StoredSession {
  id: string;
  owner: string;
  client: string | null;
  created_at: string;
}

export interface FakeServer {
  requests: RecordedRequest[];
  users: Map<string, StoredUser>;
  items: Map<string, StoredItem>;
  /** Keyed by bearer token. */
  sessions: Map<string, StoredSession>;
  expireAllSessions(): void;
  restore(): void;
}

export function installFakeServer(): FakeServer {
  const requests: RecordedRequest[] = [];
  const users = new Map<string, StoredUser>();
  const items: FakeServer['items'] = new Map();
  const sessions: FakeServer['sessions'] = new Map();
  let nextId = 1;

  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const noContent = () => new Response(null, { status: 204 });
  const publicItem = (item: StoredItem) => {
    const { owner, ...rest } = item;
    void owner;
    return rest;
  };
  const unauthorized = () =>
    json(401, { statusCode: 401, error: 'Unauthorized', message: 'Unauthorized' });

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    const headers = Object.fromEntries(
      Object.entries((init.headers ?? {}) as Record<string, string>),
    );
    const bodyText = typeof init.body === 'string' ? init.body : '';
    requests.push({ method, url, headers, body: bodyText });
    const body = bodyText ? JSON.parse(bodyText) : {};
    const path = url.replace(/^\/api/, '');

    const token = (headers.authorization ?? '').replace(/^Bearer /, '');
    const owner = sessions.get(token)?.owner;
    const now = new Date().toISOString();

    if (method === 'POST' && path === '/signup') {
      if (users.has(body.email))
        return json(409, { message: 'An account with this email already exists' });
      users.set(body.email, {
        email: body.email,
        authHash: body.auth_hash,
        encryptedVaultKey: body.encrypted_vault_key,
        vaultKeyNonce: body.vault_key_nonce,
        kdfSalt: body.kdf_salt,
        kdfParams: body.kdf_params,
        manifest: null,
        totpEnabled: false,
        recoveryCodes: [],
      });
      return json(201, { id: body.email });
    }
    if (method === 'POST' && path === '/prelogin') {
      const user = users.get(body.email);
      return json(200, {
        kdf_salt: user?.kdfSalt ?? 'AAAAAAAAAAAAAAAAAAAAAA==',
        kdf_params: user?.kdfParams ?? { memoryCost: 65536, iterations: 3, parallelism: 1 },
      });
    }
    if (method === 'POST' && path === '/login') {
      const user = users.get(body.email);
      if (!user || user.authHash !== body.auth_hash) {
        return json(401, { message: 'Invalid email or auth hash' });
      }
      if (user.totpEnabled) {
        if (!body.totp_code && !body.recovery_code) {
          return json(401, { message: 'Enter the 6-digit code.', totp_required: true });
        }
        const recoveryIndex = user.recoveryCodes.indexOf(body.recovery_code);
        if (body.totp_code !== FAKE_TOTP_CODE && recoveryIndex === -1) {
          return json(401, {
            message: 'That two-factor code is incorrect or was already used.',
            totp_required: true,
            attempts_remaining: 4,
          });
        }
        if (recoveryIndex !== -1) user.recoveryCodes.splice(recoveryIndex, 1);
      }
      const newToken = `token-${nextId++}`;
      sessions.set(newToken, {
        id: crypto.randomUUID(),
        owner: user.email,
        client: body.client ?? null,
        created_at: now,
      });
      return json(200, {
        token: newToken,
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      });
    }
    if (!owner) return unauthorized();
    const user = users.get(owner)!;
    const reauthFails = (needsFactor: boolean) => {
      if (body.current_auth_hash !== user.authHash) {
        return json(403, { message: 'Current master password is incorrect.' });
      }
      if (needsFactor && user.totpEnabled) {
        const index = user.recoveryCodes.indexOf(body.recovery_code);
        if (body.totp_code !== FAKE_TOTP_CODE && index === -1) {
          return json(403, {
            message: 'That two-factor code is incorrect or was already used.',
            totp_required: true,
          });
        }
        if (index !== -1) user.recoveryCodes.splice(index, 1);
      }
      return null;
    };
    /** Applies the write's manifest if it's the next version, like the real server. */
    const manifestConflict = (manifest: StoredManifest | undefined) => {
      const current = user.manifest?.version ?? 0;
      if (!manifest || manifest.version !== current + 1) {
        return json(409, {
          message: 'Your vault was changed elsewhere.',
          manifest_version: current,
        });
      }
      return null;
    };
    const newCodes = () =>
      Array.from({ length: 10 }, (_, i) => `CODE${i}-${Math.random().toString(36).slice(2, 7)}`);

    if (method === 'GET' && path === '/account') {
      return json(200, {
        email: user.email,
        created_at: now,
        totp_enabled: user.totpEnabled,
        recovery_codes_remaining: user.recoveryCodes.length,
      });
    }
    if (method === 'POST' && path === '/account/totp/setup') {
      if (user.totpEnabled)
        return json(409, { message: 'Two-factor authentication is already on.' });
      return json(200, {
        secret: FAKE_TOTP_SECRET,
        otpauth_uri: `otpauth://totp/VaultX:${encodeURIComponent(user.email)}?secret=${FAKE_TOTP_SECRET}&issuer=VaultX`,
      });
    }
    if (method === 'POST' && path === '/account/totp/enable') {
      const failed = reauthFails(false);
      if (failed) return failed;
      if (body.totp_code !== FAKE_TOTP_CODE)
        return json(403, { message: 'That code doesn’t match.' });
      user.totpEnabled = true;
      user.recoveryCodes = newCodes();
      return json(200, { recovery_codes: user.recoveryCodes });
    }
    if (method === 'POST' && path === '/account/totp/disable') {
      const failed = reauthFails(true);
      if (failed) return failed;
      user.totpEnabled = false;
      user.recoveryCodes = [];
      return noContent();
    }
    if (method === 'POST' && path === '/account/totp/recovery-codes') {
      const failed = reauthFails(true);
      if (failed) return failed;
      user.recoveryCodes = newCodes();
      return json(200, { recovery_codes: user.recoveryCodes });
    }
    if (method === 'DELETE' && path === '/account') {
      const failed = reauthFails(true);
      if (failed) return failed;
      users.delete(owner);
      for (const [id, item] of items) if (item.owner === owner) items.delete(id);
      for (const [t, s] of sessions) if (s.owner === owner) sessions.delete(t);
      return noContent();
    }
    if (method === 'PUT' && path === '/vault-manifest') {
      const conflict = manifestConflict(body);
      if (conflict) return conflict;
      user.manifest = body;
      return noContent();
    }

    if (method === 'POST' && path === '/logout') {
      sessions.delete(token);
      return noContent();
    }
    if (method === 'GET' && path === '/sessions') {
      const mine = [...sessions.entries()]
        .filter(([, s]) => s.owner === owner)
        .map(([t, s]) => ({
          id: s.id,
          client: s.client,
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/130.0 Safari/537.36',
          created_at: s.created_at,
          last_used_at: now,
          expires_at: now,
          current: t === token,
        }));
      return json(200, { sessions: mine });
    }
    if (method === 'DELETE' && path === '/sessions') {
      for (const [t, s] of sessions) if (s.owner === owner) sessions.delete(t);
      return noContent();
    }
    const sessionMatch = /^\/sessions\/(.+)$/.exec(path);
    if (method === 'DELETE' && sessionMatch) {
      const entry = [...sessions].find(([, s]) => s.id === sessionMatch[1] && s.owner === owner);
      if (!entry) return json(404, { message: 'Not found' });
      sessions.delete(entry[0]);
      return noContent();
    }
    if (method === 'POST' && path === '/account/password') {
      if (body.current_auth_hash !== user.authHash) {
        return json(403, { message: 'Current master password is incorrect.' });
      }
      const sent = body.items as StoredItem[];
      const mine = [...items.values()].filter((item) => item.owner === owner);
      const complete =
        sent.length === mine.length &&
        mine.every((item) =>
          sent.some((next) => next.id === item.id && next.revision === item.revision + 1),
        );
      if (!complete) return json(409, { message: 'Your vault changed while it was re-encrypted' });
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
      user.manifest = body.manifest;
      for (const next of sent) {
        Object.assign(items.get(next.id)!, {
          revision: next.revision,
          encrypted_data: next.encrypted_data,
          nonce: next.nonce,
          updated_at: now,
        });
      }
      Object.assign(user, {
        authHash: body.auth_hash,
        kdfSalt: body.kdf_salt,
        kdfParams: body.kdf_params,
        encryptedVaultKey: body.encrypted_vault_key,
        vaultKeyNonce: body.vault_key_nonce,
      });
      for (const [t, s] of sessions) if (s.owner === owner && t !== token) sessions.delete(t);
      return json(200, { items: sent.map((next) => publicItem(items.get(next.id)!)) });
    }

    if (method === 'GET' && path === '/vault-key') {
      return json(200, {
        encrypted_vault_key: user.encryptedVaultKey,
        vault_key_nonce: user.vaultKeyNonce,
        kdf_salt: user.kdfSalt,
        kdf_params: user.kdfParams,
      });
    }
    if (method === 'GET' && path === '/vault-items') {
      const mine = [...items.values()].filter((item) => item.owner === owner).map(publicItem);
      return json(200, { items: mine, manifest: user.manifest });
    }
    if (method === 'POST' && path === '/vault-items') {
      if (body.revision !== 1 || items.has(body.id)) return json(409, { message: 'Conflict' });
      const { manifest, ...fields } = body;
      const conflict = manifestConflict(manifest);
      if (conflict) return conflict;
      user.manifest = manifest;
      const item = { ...fields, owner, created_at: now, updated_at: now };
      items.set(item.id, item);
      return json(201, publicItem(item));
    }
    const match = /^\/vault-items\/(.+)$/.exec(path);
    const existing = match ? items.get(decodeURIComponent(match[1]!)) : undefined;
    if (!existing || existing.owner !== owner) return json(404, { message: 'Not found' });
    if (method === 'PUT') {
      if (body.revision !== existing.revision + 1) {
        return json(409, {
          message: 'This item was changed elsewhere since it was loaded.',
          current_revision: existing.revision,
        });
      }
      const { manifest, ...fields } = body;
      const conflict = manifestConflict(manifest);
      if (conflict) return conflict;
      user.manifest = manifest;
      Object.assign(existing, fields, { updated_at: now });
      return json(200, publicItem(existing));
    }
    if (method === 'DELETE') {
      const conflict = manifestConflict(body.manifest);
      if (conflict) return conflict;
      user.manifest = body.manifest;
      items.delete(existing.id);
      return noContent();
    }
    return json(404, { message: 'Not found' });
  });

  vi.stubGlobal('fetch', fetchMock);
  return {
    requests,
    users,
    items,
    sessions,
    expireAllSessions: () => sessions.clear(),
    restore: () => vi.unstubAllGlobals(),
  };
}
