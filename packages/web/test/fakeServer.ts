import { vi } from 'vitest';

/**
 * In-memory stand-in for packages/server that records every request the app
 * makes, so tests can assert on exactly what crosses the network.
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

export interface FakeServer {
  requests: RecordedRequest[];
  users: Map<string, StoredUser>;
  items: Map<
    string,
    {
      id: string;
      owner: string;
      encrypted_data: string;
      nonce: string;
      created_at: string;
      updated_at: string;
    }
  >;
  expireAllSessions(): void;
  restore(): void;
}

export function installFakeServer(): FakeServer {
  const requests: RecordedRequest[] = [];
  const users = new Map<string, StoredUser>();
  const items: FakeServer['items'] = new Map();
  const sessions = new Map<string, string>();
  let nextId = 1;

  const json = (status: number, body?: unknown) =>
    new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  type StoredItem = FakeServer['items'] extends Map<string, infer T> ? T : never;
  const publicItem = ({ id, encrypted_data, nonce, created_at, updated_at }: StoredItem) => ({
    id,
    encrypted_data,
    nonce,
    created_at,
    updated_at,
  });
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

    const owner = sessions.get((headers.authorization ?? '').replace(/^Bearer /, ''));
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
      const token = `token-${nextId++}`;
      sessions.set(token, user.email);
      return json(200, { token, expires_at: new Date(Date.now() + 3_600_000).toISOString() });
    }
    if (!owner) return unauthorized();
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
      const item = { id: `item-${nextId++}`, owner, ...body, created_at: now, updated_at: now };
      items.set(item.id, item);
      return json(201, publicItem(item));
    }
    const match = /^\/vault-items\/(.+)$/.exec(path);
    const existing = match ? items.get(decodeURIComponent(match[1]!)) : undefined;
    if (!existing || existing.owner !== owner) return json(404, { message: 'Not found' });
    if (method === 'PUT') {
      Object.assign(existing, body, { updated_at: now });
      return json(200, publicItem(existing));
    }
    if (method === 'DELETE') {
      items.delete(existing.id);
      return new Response(null, { status: 204 });
    }
    return json(404, { message: 'Not found' });
  });

  vi.stubGlobal('fetch', fetchMock);
  return {
    requests,
    users,
    items,
    expireAllSessions: () => sessions.clear(),
    restore: () => vi.unstubAllGlobals(),
  };
}
