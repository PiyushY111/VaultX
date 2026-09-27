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

interface StoredUser {
  email: string;
  authHash: string;
  encryptedVaultKey: string;
  vaultKeyNonce: string;
  kdfSalt: string;
  kdfParams: unknown;
}

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
      const user = users.get(owner)!;
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
      const user = users.get(owner)!;
      return json(200, {
        encrypted_vault_key: user.encryptedVaultKey,
        vault_key_nonce: user.vaultKeyNonce,
        kdf_salt: user.kdfSalt,
        kdf_params: user.kdfParams,
      });
    }
    if (method === 'GET' && path === '/vault-items') {
      const mine = [...items.values()].filter((item) => item.owner === owner).map(publicItem);
      return json(200, { items: mine });
    }
    if (method === 'POST' && path === '/vault-items') {
      if (body.revision !== 1 || items.has(body.id)) return json(409, { message: 'Conflict' });
      const item = { ...body, owner, created_at: now, updated_at: now };
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
      Object.assign(existing, body, { updated_at: now });
      return json(200, publicItem(existing));
    }
    if (method === 'DELETE') {
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
