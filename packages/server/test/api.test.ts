import { randomUUID } from 'node:crypto';
import {
  decryptItem,
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
} from '@password-manager/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  b64,
  bearer,
  createClientUser,
  createItem,
  createTestContext,
  encryptedItemPayload,
  login,
  registerAndLogin,
  signup,
  signupPayload,
  unb64,
  type ItemResponse,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await createTestContext();
});

afterAll(async () => {
  await ctx?.close();
});

describe('POST /signup', () => {
  it('creates an account and returns only its id', async () => {
    const user = await createClientUser('signup@example.com', 'pw-signup-1');
    const response = await signup(ctx.app, user);
    expect(response.statusCode).toBe(201);
    expect(Object.keys(response.json())).toEqual(['id']);
  });

  it('rejects a duplicate email, case-insensitively', async () => {
    const first = await createClientUser('dupe@example.com', 'pw-dupe');
    expect((await signup(ctx.app, first)).statusCode).toBe(201);
    const second = await createClientUser('DUPE@Example.COM', 'pw-dupe-2');
    const response = await signup(ctx.app, second);
    expect(response.statusCode).toBe(409);
  });

  describe('rejects malformed input', async () => {
    const user = await createClientUser('bad-input@example.com', 'pw-bad');
    const valid = signupPayload(user);
    const cases: [string, Record<string, unknown>][] = [
      ['missing auth_hash', { ...valid, auth_hash: undefined }],
      ['auth_hash of the wrong length', { ...valid, auth_hash: b64(new Uint8Array(31)) }],
      ['auth_hash that is not base64', { ...valid, auth_hash: '!'.repeat(44) }],
      ['kdf_salt of the wrong length', { ...valid, kdf_salt: b64(new Uint8Array(32)) }],
      [
        'vault_key_nonce of the wrong length',
        { ...valid, vault_key_nonce: b64(new Uint8Array(12)) },
      ],
      [
        'encrypted_vault_key of the wrong length',
        { ...valid, encrypted_vault_key: b64(new Uint8Array(32)) },
      ],
      ['an invalid email', { ...valid, email: 'not-an-email' }],
      [
        'memoryCost below the minimum',
        { ...valid, kdf_params: { ...user.kdfParams, memoryCost: 1024 } },
      ],
      [
        'iterations below the minimum',
        { ...valid, kdf_params: { ...user.kdfParams, iterations: 1 } },
      ],
      ['parallelism other than 1', { ...valid, kdf_params: { ...user.kdfParams, parallelism: 2 } }],
      [
        'kdf params as strings',
        { ...valid, kdf_params: { memoryCost: '19456', iterations: '2', parallelism: '1' } },
      ],
      [
        'extra kdf_params fields',
        { ...valid, kdf_params: { ...user.kdfParams, algorithm: 'md5' } },
      ],
      ['extra top-level fields', { ...valid, password: 'plaintext' }],
    ];
    it.each(cases)('%s', async (_, payload) => {
      const response = await ctx.app.inject({ method: 'POST', url: '/signup', payload });
      expect(response.statusCode, response.body).toBe(400);
    });
  });
});

describe('POST /prelogin', () => {
  it("returns a registered user's salt and params", async () => {
    const user = await createClientUser('prelogin@example.com', 'pw-prelogin');
    await signup(ctx.app, user);
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/prelogin',
      payload: { email: 'PreLogin@example.com' },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ kdf_salt: b64(user.salt), kdf_params: user.kdfParams });
  });

  it('returns a stable, plausible fake for unknown emails', async () => {
    const ask = () =>
      ctx.app.inject({
        method: 'POST',
        url: '/prelogin',
        payload: { email: 'nobody@example.com' },
      });
    const [first, second] = await Promise.all([ask(), ask()]);
    const other = await ctx.app.inject({
      method: 'POST',
      url: '/prelogin',
      payload: { email: 'nobody-else@example.com' },
    });
    expect(first.statusCode).toBe(200);
    expect(second.json()).toEqual(first.json());
    expect(unb64(first.json().kdf_salt)).toHaveLength(16);
    expect(other.json().kdf_salt).not.toBe(first.json().kdf_salt);
    expect(first.json().kdf_params).toEqual({ memoryCost: 65536, iterations: 3, parallelism: 1 });
  });
});

describe('POST /login', () => {
  it('issues a session token for the correct authHash', async () => {
    const user = await createClientUser('login@example.com', 'pw-login');
    await signup(ctx.app, user);
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: b64(user.authHash) },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(Object.keys(body).sort()).toEqual(['expires_at', 'token']);
    expect(body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now());
  });

  it('gives the same 401 for a wrong authHash and for an unknown email', async () => {
    const user = await createClientUser('login-fail@example.com', 'pw-right');
    await signup(ctx.app, user);
    const wrongKeys = await deriveKeys(
      await deriveMasterKey('pw-wrong', user.salt, user.kdfParams),
    );

    const wrongHash = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: b64(wrongKeys.authHash) },
    });
    const unknownEmail = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'ghost@example.com', auth_hash: b64(user.authHash) },
    });
    expect(wrongHash.statusCode).toBe(401);
    expect(unknownEmail.statusCode).toBe(401);
    expect(unknownEmail.json()).toEqual(wrongHash.json());
  });

  it('rejects logging in with the stored auth_hash column value (no pass-the-hash)', async () => {
    const user = await createClientUser('pass-the-hash@example.com', 'pw-pth');
    await signup(ctx.app, user);
    const { rows } = await ctx.pool.query('SELECT auth_hash FROM users WHERE email = $1', [
      user.email,
    ]);
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: rows[0].auth_hash.toString('base64') },
    });
    expect(response.statusCode).toBe(401);
  });

  it('is rate limited', async () => {
    const limited = await createTestContext({ authRateLimitMax: 3 });
    try {
      const attempt = () =>
        limited.app.inject({
          method: 'POST',
          url: '/login',
          payload: { email: 'x@example.com', auth_hash: b64(new Uint8Array(32)) },
        });
      const statuses = [];
      for (let i = 0; i < 4; i++) statuses.push((await attempt()).statusCode);
      expect(statuses).toEqual([401, 401, 401, 429]);
    } finally {
      await limited.close();
    }
  });
});

describe('authentication on protected routes', () => {
  const routes = [
    { method: 'GET', url: '/vault-key' },
    { method: 'GET', url: '/vault-items' },
    { method: 'POST', url: '/vault-items' },
    { method: 'PUT', url: `/vault-items/${randomUUID()}` },
    { method: 'DELETE', url: `/vault-items/${randomUUID()}` },
  ] as const;

  const badHeaders: [string, Record<string, string>][] = [
    ['no Authorization header', {}],
    ['a non-Bearer scheme', { authorization: 'Basic dXNlcjpwYXNz' }],
    ['a malformed token', { authorization: 'Bearer not-a-token' }],
    ['a well-formed but unknown token', bearer('A'.repeat(43))],
  ];

  for (const route of routes) {
    it.each(badHeaders)(
      `${route.method} ${route.url.replace(/[0-9a-f-]{36}/, ':id')} → 401 with %s`,
      async (_, headers) => {
        const response = await ctx.app.inject({
          method: route.method,
          url: route.url,
          headers,
          ...((route.method === 'POST' || route.method === 'PUT') && { payload: {} }),
        });
        expect(response.statusCode).toBe(401);
      },
    );
  }

  it('rejects an expired session', async () => {
    const { token } = await registerAndLogin(ctx.app, 'expired@example.com', 'pw-expired');
    const ok = await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(token) });
    expect(ok.statusCode).toBe(200);
    await ctx.pool.query(
      `UPDATE sessions SET expires_at = now() - interval '1 second'
       WHERE user_id = (SELECT id FROM users WHERE email = 'expired@example.com')`,
    );
    const expired = await ctx.app.inject({
      method: 'GET',
      url: '/vault-items',
      headers: bearer(token),
    });
    expect(expired.statusCode).toBe(401);
  });
});

describe('GET /vault-key', () => {
  it('returns what the client needs to re-derive keys and unwrap the vault key', async () => {
    const { user, token } = await registerAndLogin(
      ctx.app,
      'vault-key@example.com',
      'pw-vault-key',
    );
    const response = await ctx.app.inject({
      method: 'GET',
      url: '/vault-key',
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(Object.keys(body).sort()).toEqual([
      'encrypted_vault_key',
      'kdf_params',
      'kdf_salt',
      'vault_key_nonce',
    ]);

    // Simulate a new device: re-derive from password + returned salt/params.
    const keys = await deriveKeys(
      await deriveMasterKey(user.password, unb64(body.kdf_salt), body.kdf_params),
    );
    const vaultKey = await decryptVaultKey(
      unb64(body.encrypted_vault_key),
      unb64(body.vault_key_nonce),
      keys.stretchedMasterKey,
    );
    expect(vaultKey).toEqual(user.vaultKey);
  });
});

describe('vault items CRUD', () => {
  it('creates, lists, updates and deletes items', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'crud@example.com', 'pw-crud');
    const headers = bearer(token);

    const empty = await ctx.app.inject({ method: 'GET', url: '/vault-items', headers });
    expect(empty.json()).toEqual({ items: [] });

    const a = await createItem(ctx.app, token, user.vaultKey, '{"n":"a"}');
    const b = await createItem(ctx.app, token, user.vaultKey, '{"n":"b"}');
    expect(Object.keys(a).sort()).toEqual([
      'created_at',
      'encrypted_data',
      'id',
      'nonce',
      'updated_at',
    ]);

    const listed = (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers })).json<{
      items: ItemResponse[];
    }>();
    expect(listed.items.map((i) => i.id)).toEqual([a.id, b.id]);
    const decrypted = await Promise.all(
      listed.items.map((i) => decryptItem(unb64(i.encrypted_data), unb64(i.nonce), user.vaultKey)),
    );
    expect(decrypted).toEqual(['{"n":"a"}', '{"n":"b"}']);

    const newPayload = await encryptedItemPayload('{"n":"a2"}', user.vaultKey);
    const put = await ctx.app.inject({
      method: 'PUT',
      url: `/vault-items/${a.id}`,
      headers,
      payload: newPayload,
    });
    expect(put.statusCode).toBe(200);
    const updated = put.json<ItemResponse>();
    expect(updated.encrypted_data).toBe(newPayload.encrypted_data);
    expect(updated.nonce).toBe(newPayload.nonce);
    expect(updated.created_at).toBe(a.created_at);
    expect(new Date(updated.updated_at).getTime()).toBeGreaterThanOrEqual(
      new Date(a.updated_at).getTime(),
    );
    expect(
      await decryptItem(unb64(updated.encrypted_data), unb64(updated.nonce), user.vaultKey),
    ).toBe('{"n":"a2"}');

    const del = await ctx.app.inject({ method: 'DELETE', url: `/vault-items/${b.id}`, headers });
    expect(del.statusCode).toBe(204);
    expect(del.body).toBe('');
    const again = await ctx.app.inject({ method: 'DELETE', url: `/vault-items/${b.id}`, headers });
    expect(again.statusCode).toBe(404);

    const final = (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers })).json<{
      items: ItemResponse[];
    }>();
    expect(final.items.map((i) => i.id)).toEqual([a.id]);
  });

  it('returns 404 for unknown ids and 400 for non-UUID ids', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'ids@example.com', 'pw-ids');
    const payload = await encryptedItemPayload('{}', user.vaultKey);
    const headers = bearer(token);
    expect(
      (
        await ctx.app.inject({
          method: 'PUT',
          url: `/vault-items/${randomUUID()}`,
          headers,
          payload,
        })
      ).statusCode,
    ).toBe(404);
    expect(
      (await ctx.app.inject({ method: 'DELETE', url: `/vault-items/${randomUUID()}`, headers }))
        .statusCode,
    ).toBe(404);
    expect(
      (await ctx.app.inject({ method: 'PUT', url: '/vault-items/123', headers, payload }))
        .statusCode,
    ).toBe(400);
    expect(
      (await ctx.app.inject({ method: 'DELETE', url: '/vault-items/123', headers })).statusCode,
    ).toBe(400);
  });

  it('rejects malformed item payloads', async () => {
    const { token } = await registerAndLogin(ctx.app, 'bad-item@example.com', 'pw-bad-item');
    const headers = bearer(token);
    const payloads = [
      { encrypted_data: b64(new Uint8Array(15)), nonce: b64(new Uint8Array(24)) }, // shorter than a tag
      { encrypted_data: b64(new Uint8Array(32)), nonce: b64(new Uint8Array(12)) },
      { encrypted_data: 'not base64!', nonce: b64(new Uint8Array(24)) },
      { encrypted_data: b64(new Uint8Array(32)) },
      {
        encrypted_data: b64(new Uint8Array(32)),
        nonce: b64(new Uint8Array(24)),
        plaintext: 'hunter2',
      },
    ];
    for (const payload of payloads) {
      const response = await ctx.app.inject({
        method: 'POST',
        url: '/vault-items',
        headers,
        payload,
      });
      expect(response.statusCode, JSON.stringify(payload)).toBe(400);
    }
  });

  describe('nonce reuse', () => {
    it('rejects a new item that reuses an existing nonce', async () => {
      const { user, token } = await registerAndLogin(
        ctx.app,
        'nonce-post@example.com',
        'pw-nonce-post',
      );
      const first = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
      const response = await ctx.app.inject({
        method: 'POST',
        url: '/vault-items',
        headers: bearer(token),
        payload: { encrypted_data: first.encrypted_data, nonce: first.nonce },
      });
      expect(response.statusCode).toBe(409);
    });

    it('rejects an update that encrypts new content under the current nonce', async () => {
      const { user, token } = await registerAndLogin(
        ctx.app,
        'nonce-put@example.com',
        'pw-nonce-put',
      );
      const item = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
      const response = await ctx.app.inject({
        method: 'PUT',
        url: `/vault-items/${item.id}`,
        headers: bearer(token),
        payload: { encrypted_data: b64(new Uint8Array(40).fill(7)), nonce: item.nonce },
      });
      expect(response.statusCode).toBe(409);
    });

    it("rejects an update that reuses another item's nonce", async () => {
      const { user, token } = await registerAndLogin(
        ctx.app,
        'nonce-put2@example.com',
        'pw-nonce-put2',
      );
      const a = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
      const b = await createItem(ctx.app, token, user.vaultKey, '{"n":2}');
      const response = await ctx.app.inject({
        method: 'PUT',
        url: `/vault-items/${a.id}`,
        headers: bearer(token),
        payload: { encrypted_data: b64(new Uint8Array(40).fill(7)), nonce: b.nonce },
      });
      expect(response.statusCode).toBe(409);
    });

    it('accepts an identical retry of the current ciphertext and nonce', async () => {
      const { user, token } = await registerAndLogin(
        ctx.app,
        'nonce-retry@example.com',
        'pw-nonce-retry',
      );
      const item = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
      const response = await ctx.app.inject({
        method: 'PUT',
        url: `/vault-items/${item.id}`,
        headers: bearer(token),
        payload: { encrypted_data: item.encrypted_data, nonce: item.nonce },
      });
      expect(response.statusCode).toBe(200);
    });
  });

  it("isolates users: nobody can read, update or delete another user's items", async () => {
    const alice = await registerAndLogin(ctx.app, 'iso-alice@example.com', 'pw-iso-a');
    const mallory = await registerAndLogin(ctx.app, 'iso-mallory@example.com', 'pw-iso-m');
    const item = await createItem(ctx.app, alice.token, alice.user.vaultKey, '{"secret":true}');
    const malloryHeaders = bearer(mallory.token);

    const list = await ctx.app.inject({
      method: 'GET',
      url: '/vault-items',
      headers: malloryHeaders,
    });
    expect(list.json()).toEqual({ items: [] });

    const put = await ctx.app.inject({
      method: 'PUT',
      url: `/vault-items/${item.id}`,
      headers: malloryHeaders,
      payload: await encryptedItemPayload('{"pwned":true}', mallory.user.vaultKey),
    });
    expect(put.statusCode).toBe(404);
    const del = await ctx.app.inject({
      method: 'DELETE',
      url: `/vault-items/${item.id}`,
      headers: malloryHeaders,
    });
    expect(del.statusCode).toBe(404);

    const vaultKey = await ctx.app.inject({
      method: 'GET',
      url: '/vault-key',
      headers: malloryHeaders,
    });
    expect(vaultKey.json().encrypted_vault_key).toBe(b64(mallory.user.wrappedVaultKey.ciphertext));

    const aliceList = await ctx.app.inject({
      method: 'GET',
      url: '/vault-items',
      headers: bearer(alice.token),
    });
    expect(aliceList.json<{ items: ItemResponse[] }>().items).toEqual([item]);
  });

  it('sessions keep working independently across logins', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'multi@example.com', 'pw-multi');
    const second = await login(ctx.app, user);
    expect(second).not.toBe(token);
    for (const t of [token, second]) {
      expect(
        (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(t) }))
          .statusCode,
      ).toBe(200);
    }
  });
});
