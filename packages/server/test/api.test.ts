import { randomUUID } from 'node:crypto';
import {
  decryptItem,
  decryptManifest,
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
  nextManifest,
} from '@password-manager/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  b64,
  bearer,
  bindingOf,
  createClientUser,
  createItem,
  createTestContext,
  currentManifest,
  deleteItem,
  encryptManifestBody,
  encryptedItemPayload,
  manifestFor,
  PLACEHOLDER_MANIFEST,
  totpCode,
  login,
  registerAndLogin,
  signup,
  signupPayload,
  unb64,
  updatePayload,
  type ClientUser,
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
    { method: 'POST', url: '/logout' },
    { method: 'GET', url: '/sessions' },
    { method: 'DELETE', url: '/sessions' },
    { method: 'DELETE', url: `/sessions/${randomUUID()}` },
    { method: 'POST', url: '/account/password' },
    { method: 'PUT', url: '/vault-manifest' },
    { method: 'GET', url: '/account' },
    { method: 'POST', url: '/account/totp/setup' },
    { method: 'POST', url: '/account/totp/enable' },
    { method: 'POST', url: '/account/totp/disable' },
    { method: 'POST', url: '/account/totp/recovery-codes' },
    { method: 'DELETE', url: '/account' },
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
          ...(route.method !== 'GET' && { payload: {} }),
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
    expect(empty.json()).toEqual({ items: [], manifest: null });

    const a = await createItem(ctx.app, token, user.vaultKey, '{"n":"a"}');
    const b = await createItem(ctx.app, token, user.vaultKey, '{"n":"b"}');
    expect(Object.keys(a).sort()).toEqual([
      'created_at',
      'encrypted_data',
      'id',
      'nonce',
      'revision',
      'updated_at',
    ]);
    expect(a.revision).toBe(1);

    const listed = (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers })).json<{
      items: ItemResponse[];
    }>();
    expect(listed.items.map((i) => i.id)).toEqual([a.id, b.id]);
    const decrypted = await Promise.all(
      listed.items.map((i) =>
        decryptItem(unb64(i.encrypted_data), unb64(i.nonce), user.vaultKey, bindingOf(i)),
      ),
    );
    expect(decrypted).toEqual(['{"n":"a"}', '{"n":"b"}']);

    const newPayload = await updatePayload('{"n":"a2"}', user.vaultKey, a, {
      app: ctx.app,
      token,
    });
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
    expect(updated.revision).toBe(2);
    expect(updated.created_at).toBe(a.created_at);
    expect(new Date(updated.updated_at).getTime()).toBeGreaterThanOrEqual(
      new Date(a.updated_at).getTime(),
    );
    expect(
      await decryptItem(
        unb64(updated.encrypted_data),
        unb64(updated.nonce),
        user.vaultKey,
        bindingOf(updated),
      ),
    ).toBe('{"n":"a2"}');

    const del = await deleteItem(ctx.app, token, user.vaultKey, b.id);
    expect(del.statusCode).toBe(204);
    expect(del.body).toBe('');
    const again = await deleteItem(ctx.app, token, user.vaultKey, b.id);
    expect(again.statusCode).toBe(404);

    const final = (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers })).json<{
      items: ItemResponse[];
    }>();
    expect(final.items.map((i) => i.id)).toEqual([a.id]);
  });

  it('returns 404 for unknown ids and 400 for non-UUID ids', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'ids@example.com', 'pw-ids');
    const payload = await updatePayload('{}', user.vaultKey, { id: randomUUID(), revision: 0 });
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
    expect((await deleteItem(ctx.app, token, user.vaultKey, randomUUID())).statusCode).toBe(404);
    expect(
      (await ctx.app.inject({ method: 'PUT', url: '/vault-items/123', headers, payload }))
        .statusCode,
    ).toBe(400);
    expect(
      (
        await ctx.app.inject({
          method: 'DELETE',
          url: '/vault-items/123',
          headers,
          payload: { manifest: PLACEHOLDER_MANIFEST },
        })
      ).statusCode,
    ).toBe(400);
  });

  it('rejects malformed item payloads', async () => {
    const { token } = await registerAndLogin(ctx.app, 'bad-item@example.com', 'pw-bad-item');
    const headers = bearer(token);
    const valid = {
      id: randomUUID(),
      revision: 1,
      encrypted_data: b64(new Uint8Array(32)),
      nonce: b64(new Uint8Array(24)),
      manifest: PLACEHOLDER_MANIFEST,
    };
    const payloads = [
      { ...valid, manifest: undefined },
      { ...valid, manifest: { ...PLACEHOLDER_MANIFEST, version: 0 } },
      { ...valid, manifest: { ...PLACEHOLDER_MANIFEST, nonce: b64(new Uint8Array(12)) } },
      { ...valid, encrypted_data: b64(new Uint8Array(15)) }, // shorter than a tag
      { ...valid, nonce: b64(new Uint8Array(12)) },
      { ...valid, encrypted_data: 'not base64!' },
      { ...valid, nonce: undefined },
      { ...valid, plaintext: 'hunter2' },
      { ...valid, id: undefined },
      { ...valid, id: valid.id.toUpperCase() },
      { ...valid, id: 'item-1' },
      { ...valid, revision: undefined },
      { ...valid, revision: 0 },
      { ...valid, revision: 2 },
      { ...valid, revision: '1' },
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
        payload: {
          id: randomUUID(),
          revision: 1,
          encrypted_data: first.encrypted_data,
          nonce: first.nonce,
          manifest: PLACEHOLDER_MANIFEST,
        },
      });
      expect(response.statusCode).toBe(409);
      expect(response.json().message).toMatch(/nonce/);
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
        payload: {
          revision: 2,
          encrypted_data: b64(new Uint8Array(40).fill(7)),
          nonce: item.nonce,
          manifest: PLACEHOLDER_MANIFEST,
        },
      });
      expect(response.statusCode).toBe(409);
      expect(response.json().message).toMatch(/nonce/);
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
        payload: {
          revision: 2,
          encrypted_data: b64(new Uint8Array(40).fill(7)),
          nonce: b.nonce,
          manifest: PLACEHOLDER_MANIFEST,
        },
      });
      expect(response.statusCode).toBe(409);
      expect(response.json().message).toMatch(/nonce/);
    });

    it('accepts an identical retry of the last save', async () => {
      const { user, token } = await registerAndLogin(
        ctx.app,
        'nonce-retry@example.com',
        'pw-nonce-retry',
      );
      const item = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
      const payload = await updatePayload('{"n":2}', user.vaultKey, item, { app: ctx.app, token });
      for (let attempt = 0; attempt < 2; attempt++) {
        const response = await ctx.app.inject({
          method: 'PUT',
          url: `/vault-items/${item.id}`,
          headers: bearer(token),
          payload,
        });
        expect(response.statusCode, response.body).toBe(200);
        expect(response.json().revision).toBe(2);
      }
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
    expect(list.json()).toEqual({ items: [], manifest: null });

    const put = await ctx.app.inject({
      method: 'PUT',
      url: `/vault-items/${item.id}`,
      headers: malloryHeaders,
      payload: await updatePayload('{"pwned":true}', mallory.user.vaultKey, item),
    });
    expect(put.statusCode).toBe(404);
    // Taking over the id with a new item fails too (ids are unique across users).
    const post = await ctx.app.inject({
      method: 'POST',
      url: '/vault-items',
      headers: malloryHeaders,
      payload: {
        id: item.id,
        revision: 1,
        ...(await encryptedItemPayload('{"pwned":true}', mallory.user.vaultKey, bindingOf(item))),
        manifest: PLACEHOLDER_MANIFEST,
      },
    });
    expect(post.statusCode).toBe(409);
    const del = await deleteItem(ctx.app, mallory.token, mallory.user.vaultKey, item.id);
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

describe('item revisions', () => {
  it('accepts only the next revision, and reports the current one on a conflict', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'rev@example.com', 'pw-rev');
    const headers = bearer(token);
    const item = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
    const put = (payload: object) =>
      ctx.app.inject({ method: 'PUT', url: `/vault-items/${item.id}`, headers, payload });

    const second = await put(
      await updatePayload('{"n":2}', user.vaultKey, item, { app: ctx.app, token }),
    );
    expect(second.statusCode, second.body).toBe(200);

    // A client that loaded revision 1 tries to save its own revision 2.
    const stale = await put(await updatePayload('{"n":"stale"}', user.vaultKey, item));
    expect(stale.statusCode).toBe(409);
    expect(stale.json()).toMatchObject({ current_revision: 2, message: /changed elsewhere/ });

    const skipped = await put(
      await updatePayload('{"n":4}', user.vaultKey, { id: item.id, revision: 3 }),
    );
    expect(skipped.statusCode).toBe(409);

    const listed = (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers })).json<{
      items: ItemResponse[];
    }>();
    expect(listed.items).toEqual([second.json()]);
  });

  it('lets a client re-save an item from before revisions existed as revision 1', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'legacy@example.com', 'pw-legacy');
    const id = randomUUID();
    await ctx.pool.query(
      `INSERT INTO vault_items (id, user_id, revision, encrypted_data, nonce)
       SELECT $1, id, 0, $2, $3 FROM users WHERE email = 'legacy@example.com'`,
      [id, Buffer.alloc(40, 1), Buffer.alloc(24, 2)],
    );
    const response = await ctx.app.inject({
      method: 'PUT',
      url: `/vault-items/${id}`,
      headers: bearer(token),
      payload: await updatePayload(
        '{"n":1}',
        user.vaultKey,
        { id, revision: 0 },
        { app: ctx.app, token },
      ),
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json().revision).toBe(1);
  });

  it('rejects a second item with the same id', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'dupe-id@example.com', 'pw-dupe-id');
    const item = await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/vault-items',
      headers: bearer(token),
      payload: {
        id: item.id,
        revision: 1,
        ...(await encryptedItemPayload('{"n":2}', user.vaultKey, bindingOf(item))),
        manifest: PLACEHOLDER_MANIFEST,
      },
    });
    expect(response.statusCode).toBe(409);
    expect(response.json().message).toMatch(/already exists/);
  });
});

describe('sessions', () => {
  const listSessions = async (token: string) => {
    const response = await ctx.app.inject({
      method: 'GET',
      url: '/sessions',
      headers: bearer(token),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ sessions: Record<string, unknown>[] }>().sessions;
  };
  const status = async (token: string) =>
    (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(token) }))
      .statusCode;

  it("lists the account's live sessions and marks the current one", async () => {
    const { user, token: webToken } = await registerAndLogin(
      ctx.app,
      'sessions@example.com',
      'pw-sessions',
    );
    const extensionToken = await login(ctx.app, user, {
      client: 'extension',
      headers: { 'user-agent': 'TestAgent/1.0' },
    });
    const expired = await login(ctx.app, user);
    await ctx.pool.query(
      `UPDATE sessions SET expires_at = now() - interval '1 second'
       WHERE last_used_at = (SELECT max(last_used_at) FROM sessions)`,
    );
    expect(await status(expired)).toBe(401);
    await registerAndLogin(ctx.app, 'sessions-other@example.com', 'pw-sessions-other');

    const sessions = await listSessions(extensionToken);
    expect(sessions).toHaveLength(2);
    const current = sessions.find((session) => session.current)!;
    expect(Object.keys(current).sort()).toEqual([
      'client',
      'created_at',
      'current',
      'expires_at',
      'id',
      'last_used_at',
      'user_agent',
    ]);
    expect(current).toMatchObject({ client: 'extension', user_agent: 'TestAgent/1.0' });
    expect(sessions.filter((session) => !session.current)).toHaveLength(1);
    expect(await listSessions(webToken)).toHaveLength(2);
  });

  it('rejects an unknown client label and truncates long user agents', async () => {
    const user = await createClientUser('ua@example.com', 'pw-ua');
    expect((await signup(ctx.app, user)).statusCode).toBe(201);
    const bad = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: b64(user.authHash), client: 'curl' },
    });
    expect(bad.statusCode).toBe(400);

    const token = await login(ctx.app, user, { headers: { 'user-agent': 'x'.repeat(1000) } });
    const [session] = await listSessions(token);
    expect(session!.user_agent).toBe('x'.repeat(256));
  });

  it('records when a session was last used', async () => {
    const { token } = await registerAndLogin(ctx.app, 'last-used@example.com', 'pw-last-used');
    await ctx.pool.query(
      `UPDATE sessions SET last_used_at = now() - interval '1 hour'
       WHERE user_id = (SELECT id FROM users WHERE email = 'last-used@example.com')`,
    );
    const [session] = await listSessions(token);
    expect(Date.now() - new Date(session!.last_used_at as string).getTime()).toBeLessThan(60_000);
  });

  it('POST /logout ends only the current session', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'logout@example.com', 'pw-logout');
    const other = await login(ctx.app, user);
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/logout',
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(204);
    expect(await status(token)).toBe(401);
    expect(await status(other)).toBe(200);
  });

  it('DELETE /sessions/:id revokes one session, only within the account', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'revoke@example.com', 'pw-revoke');
    const other = await login(ctx.app, user);
    const mallory = await registerAndLogin(ctx.app, 'revoke-mallory@example.com', 'pw-mal');
    const otherId = (await listSessions(token)).find((session) => !session.current)!.id;

    const foreign = await ctx.app.inject({
      method: 'DELETE',
      url: `/sessions/${otherId}`,
      headers: bearer(mallory.token),
    });
    expect(foreign.statusCode).toBe(404);
    expect(await status(other)).toBe(200);

    const response = await ctx.app.inject({
      method: 'DELETE',
      url: `/sessions/${otherId}`,
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(204);
    expect(await status(other)).toBe(401);
    expect(await status(token)).toBe(200);
  });

  it('DELETE /sessions signs out everywhere, and only this account', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'everywhere@example.com', 'pw-every');
    const other = await login(ctx.app, user);
    const bystander = await registerAndLogin(ctx.app, 'bystander@example.com', 'pw-bystander');
    const response = await ctx.app.inject({
      method: 'DELETE',
      url: '/sessions',
      headers: bearer(token),
    });
    expect(response.statusCode).toBe(204);
    expect(await status(token)).toBe(401);
    expect(await status(other)).toBe(401);
    expect(await status(bystander.token)).toBe(200);
  });
});

describe('POST /account/password', () => {
  /** The client side of a password change: new keys, a new vault key, every item re-encrypted. */
  async function changePasswordBody(
    user: ClientUser,
    token: string,
    newPassword: string,
    items: { item: ItemResponse; plaintext: string }[],
  ) {
    const next = await createClientUser(user.email, newPassword);
    const current = await currentManifest(ctx.app, token, user.vaultKey);
    const manifest = await encryptManifestBody(
      nextManifest(
        current,
        { set: items.map(({ item }) => ({ id: item.id, revision: item.revision + 1 })) },
        'test',
      ),
      next.vaultKey,
    );
    const body = {
      manifest,
      current_auth_hash: b64(user.authHash),
      auth_hash: b64(next.authHash),
      kdf_salt: b64(next.salt),
      kdf_params: next.kdfParams,
      encrypted_vault_key: b64(next.wrappedVaultKey.ciphertext),
      vault_key_nonce: b64(next.wrappedVaultKey.nonce),
      items: await Promise.all(
        items.map(async ({ item, plaintext }) => ({
          id: item.id,
          ...(await updatePayload(plaintext, next.vaultKey, item)),
          manifest: undefined,
        })),
      ),
    };
    return { next, body };
  }

  const changePassword = (token: string, payload: object) =>
    ctx.app.inject({ method: 'POST', url: '/account/password', headers: bearer(token), payload });

  const loginStatus = async (user: ClientUser) =>
    (
      await ctx.app.inject({
        method: 'POST',
        url: '/login',
        payload: { email: user.email, auth_hash: b64(user.authHash) },
      })
    ).statusCode;

  it('changes the password, rotates the vault key and ends the other sessions', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'change@example.com', 'pw-change');
    const otherSession = await login(ctx.app, user);
    const a = await createItem(ctx.app, token, user.vaultKey, '{"n":"a"}');
    const b = await createItem(ctx.app, token, user.vaultKey, '{"n":"b"}');

    const { next, body } = await changePasswordBody(user, token, 'pw-change-NEW', [
      { item: b, plaintext: '{"n":"b"}' },
      { item: a, plaintext: '{"n":"a"}' },
    ]);
    const response = await changePassword(token, body);
    expect(response.statusCode, response.body).toBe(200);
    const returned = response.json<{ items: ItemResponse[] }>().items;
    expect(returned.map((item) => [item.id, item.revision])).toEqual([
      [b.id, 2],
      [a.id, 2],
    ]);

    // Items now decrypt under the new vault key only.
    const listed = (
      await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(token) })
    ).json<{ items: ItemResponse[] }>().items;
    for (const item of listed) {
      const plaintext = await decryptItem(
        unb64(item.encrypted_data),
        unb64(item.nonce),
        next.vaultKey,
        bindingOf(item),
      );
      expect(plaintext).toBe(item.id === a.id ? '{"n":"a"}' : '{"n":"b"}');
    }

    // The new password unwraps the new vault key; the old one no longer logs in.
    const wrapped = (
      await ctx.app.inject({ method: 'GET', url: '/vault-key', headers: bearer(token) })
    ).json();
    const keys = await deriveKeys(
      await deriveMasterKey('pw-change-NEW', unb64(wrapped.kdf_salt), wrapped.kdf_params),
    );
    expect(
      await decryptVaultKey(
        unb64(wrapped.encrypted_vault_key),
        unb64(wrapped.vault_key_nonce),
        keys.stretchedMasterKey,
      ),
    ).toEqual(next.vaultKey);
    expect(await loginStatus(user)).toBe(401);
    expect(await loginStatus(next)).toBe(200);

    // This session continues; the others held the old vault key and are ended.
    const status = async (t: string) =>
      (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(t) })).statusCode;
    expect(await status(token)).toBe(200);
    expect(await status(otherSession)).toBe(401);
  });

  it('works for an empty vault', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'change-empty@example.com', 'pw-e');
    const { next, body } = await changePasswordBody(user, token, 'pw-e-NEW', []);
    expect((await changePassword(token, body)).statusCode).toBe(200);
    expect(await loginStatus(next)).toBe(200);
  });

  it('refuses a wrong current password with 403, and counts it toward the login lockout', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'change-wrong@example.com', 'pw-w');
    const { body } = await changePasswordBody(user, token, 'pw-w-NEW', []);
    const wrong = { ...body, current_auth_hash: b64(new Uint8Array(32).fill(9)) };

    const first = await changePassword(token, wrong);
    expect(first.statusCode).toBe(403);
    expect(first.json()).toMatchObject({ attempts_remaining: 4 });
    for (let i = 0; i < 4; i++) expect((await changePassword(token, wrong)).statusCode).toBe(403);
    // Budget spent: even the right password is refused for now, and so is logging in.
    expect((await changePassword(token, body)).statusCode).toBe(429);
    expect(await loginStatus(user)).toBe(429);
    // Nothing changed.
    await ctx.pool.query("DELETE FROM login_failures WHERE email = 'change-wrong@example.com'");
    expect(await loginStatus(user)).toBe(200);
  });

  it('refuses an item set that is incomplete, stale or padded, changing nothing', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'change-409@example.com', 'pw-409');
    const a = await createItem(ctx.app, token, user.vaultKey, '{"n":"a"}');
    const b = await createItem(ctx.app, token, user.vaultKey, '{"n":"b"}');
    const both = [
      { item: a, plaintext: 'a' },
      { item: b, plaintext: 'b' },
    ];
    const { body } = await changePasswordBody(user, token, 'pw-409-NEW', both);
    const [itemA, itemB] = body.items;

    const cases = {
      'missing an item': [itemA],
      'repeating an item': [itemA, itemA],
      'with an item at the wrong revision': [itemA, { ...itemB!, revision: 3 }],
      'with an extra item': [itemA, itemB, { ...itemB!, id: randomUUID() }],
    };
    for (const [name, items] of Object.entries(cases)) {
      const response = await changePassword(token, { ...body, items });
      expect(response.statusCode, name).toBe(409);
    }
    // The current password was right each time, so none of that used up login attempts.
    const { rows } = await ctx.pool.query(
      "SELECT 1 FROM login_failures WHERE email = 'change-409@example.com'",
    );
    expect(rows).toEqual([]);
    expect(await loginStatus(user)).toBe(200);
    const listed = (
      await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(token) })
    ).json<{ items: ItemResponse[] }>().items;
    expect(listed).toEqual([a, b]);
  });

  it('rejects KDF params below the floor', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'change-kdf@example.com', 'pw-kdf');
    const { body } = await changePasswordBody(user, token, 'pw-kdf-NEW', []);
    const response = await changePassword(token, {
      ...body,
      kdf_params: { ...body.kdf_params, memoryCost: 1024 },
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('vault manifest', () => {
  const vault = async (token: string) =>
    (await ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(token) })).json<{
      items: ItemResponse[];
      manifest: { version: number; encrypted_data: string; nonce: string } | null;
    }>();

  it('moves to the next version with every item write, and stores it as sent', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'manifest@example.com', 'pw-m');
    expect((await vault(token)).manifest).toBeNull();

    const a = await createItem(ctx.app, token, user.vaultKey, '{"n":"a"}');
    const b = await createItem(ctx.app, token, user.vaultKey, '{"n":"b"}');
    const put = await ctx.app.inject({
      method: 'PUT',
      url: `/vault-items/${a.id}`,
      headers: bearer(token),
      payload: await updatePayload('{"n":"a2"}', user.vaultKey, a, { app: ctx.app, token }),
    });
    expect(put.statusCode, put.body).toBe(200);
    expect((await deleteItem(ctx.app, token, user.vaultKey, b.id)).statusCode).toBe(204);

    const { manifest } = await vault(token);
    expect(manifest!.version).toBe(4);
    const decrypted = await decryptManifest(
      unb64(manifest!.encrypted_data),
      unb64(manifest!.nonce),
      user.vaultKey,
      manifest!.version,
    );
    expect(decrypted.items).toEqual({ [a.id]: 2 });
  });

  it('refuses a write whose manifest is not the next version, and then changes nothing', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'manifest-409@example.com', 'pw-m');
    await createItem(ctx.app, token, user.vaultKey, '{"n":"a"}');
    const stale = await encryptManifestBody(
      nextManifest(null, { set: [{ id: randomUUID(), revision: 1 }] }, 'test'),
      user.vaultKey,
    );
    const id = randomUUID();
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/vault-items',
      headers: bearer(token),
      payload: {
        id,
        revision: 1,
        ...(await encryptedItemPayload('{}', user.vaultKey, { itemId: id, revision: 1 })),
        manifest: stale, // version 1, but the vault is at 1 already
      },
    });
    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ manifest_version: 1 });
    // The item wasn't stored either: writes are all-or-nothing.
    expect((await vault(token)).items.map((item) => item.id)).not.toContain(id);
  });

  it('PUT /vault-manifest writes a first manifest for an existing vault', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'manifest-init@example.com', 'pw-m');
    const put = (manifest: object) =>
      ctx.app.inject({
        method: 'PUT',
        url: '/vault-manifest',
        headers: bearer(token),
        payload: manifest,
      });
    const first = await manifestFor(ctx.app, token, user.vaultKey, {});
    expect((await put(first)).statusCode).toBe(204);
    expect((await put(first)).statusCode).toBe(409);
    expect((await vault(token)).manifest!.version).toBe(1);
  });

  it("is never another user's", async () => {
    const alice = await registerAndLogin(ctx.app, 'manifest-a@example.com', 'pw-a');
    const bob = await registerAndLogin(ctx.app, 'manifest-b@example.com', 'pw-b');
    await createItem(ctx.app, alice.token, alice.user.vaultKey, '{}');
    expect((await vault(bob.token)).manifest).toBeNull();
  });
});

describe('two-factor login', () => {
  async function enableTwoFactor(email: string) {
    const { user, token } = await registerAndLogin(ctx.app, email, 'pw-2fa');
    const setup = await ctx.app.inject({
      method: 'POST',
      url: '/account/totp/setup',
      headers: bearer(token),
    });
    expect(setup.statusCode, setup.body).toBe(200);
    const { secret, otpauth_uri } = setup.json<{ secret: string; otpauth_uri: string }>();
    expect(otpauth_uri).toContain(`secret=${secret}`);
    const enable = await ctx.app.inject({
      method: 'POST',
      url: '/account/totp/enable',
      headers: bearer(token),
      payload: { current_auth_hash: b64(user.authHash), totp_code: totpCode(secret) },
    });
    expect(enable.statusCode, enable.body).toBe(200);
    const recoveryCodes = enable.json<{ recovery_codes: string[] }>().recovery_codes;
    // The code just used can't log in; wait for the next step instead of sleeping.
    await ctx.pool.query('UPDATE users SET totp_last_step = totp_last_step - 1 WHERE email = $1', [
      email,
    ]);
    return { user, token, secret, recoveryCodes };
  }

  const loginWith = (user: ClientUser, extra: Record<string, string> = {}) =>
    ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: b64(user.authHash), ...extra },
    });

  it('is set up with a code from the app, and reported by GET /account', async () => {
    const { token, recoveryCodes } = await enableTwoFactor('2fa-setup@example.com');
    expect(recoveryCodes).toHaveLength(10);
    const account = await ctx.app.inject({
      method: 'GET',
      url: '/account',
      headers: bearer(token),
    });
    expect(account.json()).toMatchObject({
      email: '2fa-setup@example.com',
      totp_enabled: true,
      recovery_codes_remaining: 10,
    });
    const again = await ctx.app.inject({
      method: 'POST',
      url: '/account/totp/setup',
      headers: bearer(token),
    });
    expect(again.statusCode).toBe(409);
  });

  it('refuses to turn on with a wrong code or without the master password', async () => {
    const { user, token } = await registerAndLogin(ctx.app, '2fa-wrong@example.com', 'pw');
    const { secret } = (
      await ctx.app.inject({ method: 'POST', url: '/account/totp/setup', headers: bearer(token) })
    ).json();
    const enable = (payload: object) =>
      ctx.app.inject({
        method: 'POST',
        url: '/account/totp/enable',
        headers: bearer(token),
        payload,
      });
    const wrongCode = String((Number(totpCode(secret)) + 1) % 1_000_000).padStart(6, '0');
    expect(
      (await enable({ current_auth_hash: b64(user.authHash), totp_code: wrongCode })).statusCode,
    ).toBe(403);
    expect(
      (
        await enable({
          current_auth_hash: b64(new Uint8Array(32).fill(5)),
          totp_code: totpCode(secret),
        })
      ).statusCode,
    ).toBe(403);
    expect((await loginWith(user)).statusCode).toBe(200);
  });

  it('asks for a code only after the password is right, without using up an attempt', async () => {
    const { user } = await enableTwoFactor('2fa-login@example.com');
    const wrongPassword = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: b64(new Uint8Array(32).fill(1)) },
    });
    expect(wrongPassword.statusCode).toBe(401);
    expect(wrongPassword.json()).not.toHaveProperty('totp_required');

    for (let i = 0; i < 6; i++) {
      const response = await loginWith(user);
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({ totp_required: true });
    }
    // Still 4 attempts left: only the wrong password counted.
    const wrongCode = await loginWith(user, { totp_code: '000000' });
    expect(wrongCode.json()).toMatchObject({ totp_required: true, attempts_remaining: 3 });
  });

  it('logs in with the current code, once', async () => {
    const { user, secret } = await enableTwoFactor('2fa-code@example.com');
    const code = totpCode(secret);
    expect((await loginWith(user, { totp_code: code })).statusCode).toBe(200);
    const replay = await loginWith(user, { totp_code: code });
    expect(replay.statusCode).toBe(401);
    expect(replay.json()).toMatchObject({ totp_required: true });
  });

  it('logs in with a recovery code, once, in any case or spacing', async () => {
    const { user, token, recoveryCodes } = await enableTwoFactor('2fa-recovery@example.com');
    const code = recoveryCodes[0]!;
    expect(
      (await loginWith(user, { recovery_code: code.toLowerCase().replace('-', ' ') })).statusCode,
    ).toBe(200);
    expect((await loginWith(user, { recovery_code: code })).statusCode).toBe(401);
    const account = await ctx.app.inject({
      method: 'GET',
      url: '/account',
      headers: bearer(token),
    });
    expect(account.json().recovery_codes_remaining).toBe(9);
  });

  it('counts wrong codes toward the lockout', async () => {
    const { user, secret } = await enableTwoFactor('2fa-lockout@example.com');
    for (let i = 0; i < 5; i++) {
      expect((await loginWith(user, { totp_code: '000000' })).statusCode).toBe(401);
    }
    expect((await loginWith(user, { totp_code: totpCode(secret) })).statusCode).toBe(429);
  });

  it('turns off only with the master password and a code', async () => {
    const { user, token, secret } = await enableTwoFactor('2fa-off@example.com');
    const disable = (payload: object) =>
      ctx.app.inject({
        method: 'POST',
        url: '/account/totp/disable',
        headers: bearer(token),
        payload,
      });
    const withoutCode = await disable({ current_auth_hash: b64(user.authHash) });
    expect(withoutCode.statusCode).toBe(403);
    expect(withoutCode.json()).toMatchObject({ totp_required: true });
    expect(
      (await disable({ current_auth_hash: b64(user.authHash), totp_code: totpCode(secret) }))
        .statusCode,
    ).toBe(204);
    expect((await loginWith(user)).statusCode).toBe(200);
    const { rows } = await ctx.pool.query(
      `SELECT 1 FROM totp_recovery_codes WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
      [user.email],
    );
    expect(rows).toEqual([]);
  });

  it('issues new recovery codes, replacing the old ones', async () => {
    const { user, token, secret, recoveryCodes } = await enableTwoFactor('2fa-regen@example.com');
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/account/totp/recovery-codes',
      headers: bearer(token),
      payload: { current_auth_hash: b64(user.authHash), totp_code: totpCode(secret) },
    });
    expect(response.statusCode, response.body).toBe(200);
    const fresh = response.json<{ recovery_codes: string[] }>().recovery_codes;
    expect(fresh).toHaveLength(10);
    expect((await loginWith(user, { recovery_code: recoveryCodes[0]! })).statusCode).toBe(401);
    expect((await loginWith(user, { recovery_code: fresh[0]! })).statusCode).toBe(200);
  });
});

describe('DELETE /account', () => {
  const remove = (token: string, payload: object) =>
    ctx.app.inject({ method: 'DELETE', url: '/account', headers: bearer(token), payload });

  it('deletes the account and everything in it, after checking the password', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'delete-me@example.com', 'pw-del');
    await createItem(ctx.app, token, user.vaultKey, '{"n":1}');
    const bystander = await registerAndLogin(ctx.app, 'delete-bystander@example.com', 'pw-b');

    expect((await remove(token, { current_auth_hash: b64(new Uint8Array(32)) })).statusCode).toBe(
      403,
    );
    expect((await remove(token, { current_auth_hash: b64(user.authHash) })).statusCode).toBe(204);

    const status = await ctx.app.inject({
      method: 'GET',
      url: '/vault-items',
      headers: bearer(token),
    });
    expect(status.statusCode).toBe(401);
    const login = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: b64(user.authHash) },
    });
    expect(login.statusCode).toBe(401);
    const { rows } = await ctx.pool.query(
      `SELECT (SELECT count(*) FROM users WHERE email = $1)::int AS users,
              (SELECT count(*) FROM vault_items v JOIN users u ON u.id = v.user_id
                WHERE u.email = $2)::int AS bystander_items`,
      [user.email, bystander.user.email],
    );
    expect(rows[0]).toEqual({ users: 0, bystander_items: 0 });
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: '/vault-items',
          headers: bearer(bystander.token),
        })
      ).statusCode,
    ).toBe(200);
  });

  it('also needs a two-factor code when two-factor is on', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'delete-2fa@example.com', 'pw');
    const { secret } = (
      await ctx.app.inject({ method: 'POST', url: '/account/totp/setup', headers: bearer(token) })
    ).json();
    await ctx.app.inject({
      method: 'POST',
      url: '/account/totp/enable',
      headers: bearer(token),
      payload: { current_auth_hash: b64(user.authHash), totp_code: totpCode(secret) },
    });
    const withoutCode = await remove(token, { current_auth_hash: b64(user.authHash) });
    expect(withoutCode.statusCode).toBe(403);
    expect(withoutCode.json()).toMatchObject({ totp_required: true });
    await ctx.pool.query('UPDATE users SET totp_last_step = 0 WHERE email = $1', [user.email]);
    expect(
      (await remove(token, { current_auth_hash: b64(user.authHash), totp_code: totpCode(secret) }))
        .statusCode,
    ).toBe(204);
  });
});
