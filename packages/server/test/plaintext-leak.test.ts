import { createHash } from 'node:crypto';
import { DecryptionError, decryptItem, decryptVaultKey } from '@password-manager/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  b64,
  bearer,
  createClientUser,
  createItem,
  createTestContext,
  listTables,
  login,
  registerAndLogin,
  scanDatabaseForSecrets,
  unb64,
  updatePayload,
  type ClientUser,
  type ItemResponse,
  type Secret,
  type TestContext,
} from './helpers.js';

// Distinctive markers so a hit can only mean a real leak, never a chance
// match inside random ciphertext.
const ALICE_PASSWORD = 'alice-MASTER-PASSWORD-correct-horse-7c1e';
const BOB_PASSWORD = 'bob-MASTER-PASSWORD-tr0ub4dor-3d91';
const BOB_NEW_PASSWORD = 'bob-NEW-MASTER-PASSWORD-after-change-5e2a';

interface PlainItem {
  site: string;
  username: string;
  password: string;
  notes: string;
}

const item = (tag: string): PlainItem => ({
  site: `https://${tag}-site.example.com/login`,
  username: `${tag}-username@example.com`,
  password: `${tag}-ITEM-PASSWORD-s3cr3t!`,
  notes: `${tag}-private notes: recovery codes 1234-5678`,
});

const ALICE_ITEMS = [item('alice-bank'), item('alice-email'), item('alice-social')];
const ALICE_ITEM_UPDATED = item('alice-bank-rotated');
const BOB_ITEMS = [item('bob-work')];

function itemSecrets(prefix: string, plain: PlainItem): Secret[] {
  return [
    { name: `${prefix} JSON`, value: JSON.stringify(plain) },
    ...Object.entries(plain).map(([field, value]) => ({ name: `${prefix}.${field}`, value })),
  ];
}

function userSecrets(label: string, user: ClientUser, tokens: string[]): Secret[] {
  return [
    { name: `${label} master password`, value: user.password },
    { name: `${label} master key`, value: user.masterKey },
    { name: `${label} stretched master key`, value: user.stretchedMasterKey },
    { name: `${label} raw authHash`, value: user.authHash },
    { name: `${label} vault key`, value: user.vaultKey },
    ...tokens.map((token, i) => ({ name: `${label} session token #${i + 1}`, value: token })),
  ];
}

describe('raw database rows never contain plaintext or key material', () => {
  let ctx: TestContext;
  let alice: ClientUser;
  let bob: ClientUser;
  /** Bob before his password change (old keys, old vault key). */
  let bobBefore: ClientUser;
  let aliceTokens: string[];
  let bobTokens: string[];
  let secrets: Secret[];
  /** What the client sent for each live item, keyed by item id. */
  const sentItems = new Map<
    string,
    {
      revision: number;
      ciphertext: string;
      nonce: string;
      plaintext: string;
      owner: 'alice' | 'bob';
    }
  >();

  beforeAll(async () => {
    ctx = await createTestContext();
    const { app } = ctx;

    const a = await registerAndLogin(app, 'Alice@Example.com', ALICE_PASSWORD);
    const b = await registerAndLogin(app, 'bob@example.com', BOB_PASSWORD);
    alice = a.user;
    bob = b.user;
    aliceTokens = [a.token, await login(app, alice)];
    bobTokens = [b.token];

    const record = (created: ItemResponse, plaintext: string, owner: 'alice' | 'bob') =>
      sentItems.set(created.id, {
        revision: created.revision,
        ciphertext: created.encrypted_data,
        nonce: created.nonce,
        plaintext,
        owner,
      });

    const aliceCreated: ItemResponse[] = [];
    for (const plain of ALICE_ITEMS) {
      const json = JSON.stringify(plain);
      const created = await createItem(app, a.token, alice.vaultKey, json);
      aliceCreated.push(created);
      record(created, json, 'alice');
    }
    const bobCreated: { item: ItemResponse; json: string }[] = [];
    for (const plain of BOB_ITEMS) {
      const json = JSON.stringify(plain);
      const created = await createItem(app, b.token, bob.vaultKey, json);
      bobCreated.push({ item: created, json });
      record(created, json, 'bob');
    }

    // Bob changes his master password, which re-encrypts his items under a new vault key.
    bobBefore = bob;
    bob = await createClientUser(bob.email, BOB_NEW_PASSWORD);
    const reencrypted = await Promise.all(
      bobCreated.map(async ({ item: created, json }) => ({
        id: created.id,
        ...(await updatePayload(json, bob.vaultKey, created)),
      })),
    );
    const change = await app.inject({
      method: 'POST',
      url: '/account/password',
      headers: bearer(b.token),
      payload: {
        current_auth_hash: b64(bobBefore.authHash),
        auth_hash: b64(bob.authHash),
        kdf_salt: b64(bob.salt),
        kdf_params: bob.kdfParams,
        encrypted_vault_key: b64(bob.wrappedVaultKey.ciphertext),
        vault_key_nonce: b64(bob.wrappedVaultKey.nonce),
        items: reencrypted,
      },
    });
    expect(change.statusCode, change.body).toBe(200);
    for (const [i, sent] of reencrypted.entries()) {
      sentItems.set(sent.id, {
        revision: sent.revision,
        ciphertext: sent.encrypted_data,
        nonce: sent.nonce,
        plaintext: bobCreated[i]!.json,
        owner: 'bob',
      });
    }

    // Update alice's first item, delete her third.
    const updatedJson = JSON.stringify(ALICE_ITEM_UPDATED);
    const payload = await updatePayload(updatedJson, alice.vaultKey, aliceCreated[0]!);
    const put = await app.inject({
      method: 'PUT',
      url: `/vault-items/${aliceCreated[0]!.id}`,
      headers: bearer(a.token),
      payload,
    });
    expect(put.statusCode, put.body).toBe(200);
    sentItems.set(aliceCreated[0]!.id, {
      revision: payload.revision,
      ciphertext: payload.encrypted_data,
      nonce: payload.nonce,
      plaintext: updatedJson,
      owner: 'alice',
    });
    const del = await app.inject({
      method: 'DELETE',
      url: `/vault-items/${aliceCreated[2]!.id}`,
      headers: bearer(a.token),
    });
    expect(del.statusCode).toBe(204);
    sentItems.delete(aliceCreated[2]!.id);

    secrets = [
      ...userSecrets('alice', alice, aliceTokens),
      ...userSecrets('bob', bob, bobTokens),
      ...userSecrets('bob (before password change)', bobBefore, []),
      ...ALICE_ITEMS.flatMap((plain, i) => itemSecrets(`alice item ${i}`, plain)),
      ...itemSecrets('alice updated item', ALICE_ITEM_UPDATED),
      ...BOB_ITEMS.flatMap((plain, i) => itemSecrets(`bob item ${i}`, plain)),
    ];
  });

  afterAll(async () => {
    await ctx?.close();
  });

  it('scans every table in the schema', async () => {
    expect(await listTables(ctx.pool)).toEqual([
      'login_failures',
      'schema_migrations',
      'sessions',
      'users',
      'vault_items',
    ]);
  });

  it('finds no master password, item plaintext, key, raw authHash or session token in any cell, in any encoding', async () => {
    const leaks = await scanDatabaseForSecrets(ctx.pool, secrets);
    expect(leaks).toEqual([]);
    // Sanity check that the scan covered what we think it did: 3 key sets
    // (alice, bob before and after his password change) x (5 keys/passwords) + 3 session tokens + 5 items x (JSON + 4 fields).
    expect(secrets).toHaveLength(3 * 5 + 3 + 5 * 5);
  });

  it('users: stores only a hash of the authHash, plus ciphertext, nonce, salt and params exactly as sent', async () => {
    const { rows } = await ctx.pool.query('SELECT * FROM users ORDER BY email');
    expect(rows.map((row) => row.email)).toEqual(['alice@example.com', 'bob@example.com']);
    expect(Object.keys(rows[0]).sort()).toEqual(
      [
        'auth_hash',
        'created_at',
        'email',
        'encrypted_vault_key',
        'id',
        'kdf_params',
        'kdf_salt',
        'vault_key_nonce',
      ].sort(),
    );

    for (const [row, user] of [
      [rows[0], alice],
      [rows[1], bob],
    ] as const) {
      expect(row.auth_hash).toHaveLength(32);
      expect(Buffer.compare(row.auth_hash, Buffer.from(user.authHash))).not.toBe(0);
      expect(row.encrypted_vault_key).toHaveLength(48);
      expect(row.encrypted_vault_key).toEqual(Buffer.from(user.wrappedVaultKey.ciphertext));
      expect(row.vault_key_nonce).toHaveLength(24);
      expect(row.vault_key_nonce).toEqual(Buffer.from(user.wrappedVaultKey.nonce));
      expect(row.kdf_salt).toEqual(Buffer.from(user.salt));
      expect(row.kdf_params).toEqual(user.kdfParams);

      // The stored bytes are real ciphertext: only the client's key opens them.
      const unwrapped = await decryptVaultKey(
        row.encrypted_vault_key,
        row.vault_key_nonce,
        user.stretchedMasterKey,
      );
      expect(unwrapped).toEqual(user.vaultKey);
      await expect(
        decryptVaultKey(row.encrypted_vault_key, row.vault_key_nonce, user.authHash),
      ).rejects.toThrow(DecryptionError);
    }
  });

  it('vault_items: stores exactly the ciphertext and nonce the client sent, nothing else', async () => {
    const { rows } = await ctx.pool.query('SELECT * FROM vault_items');
    expect(Object.keys(rows[0]).sort()).toEqual(
      ['created_at', 'encrypted_data', 'id', 'nonce', 'revision', 'updated_at', 'user_id'].sort(),
    );
    expect(rows).toHaveLength(sentItems.size);

    for (const row of rows) {
      const sent = sentItems.get(row.id)!;
      expect(sent, `unexpected row ${row.id}`).toBeDefined();
      const owner = sent.owner === 'alice' ? alice : bob;
      expect(row.nonce).toHaveLength(24);
      expect(row.nonce).toEqual(Buffer.from(unb64(sent.nonce)));
      expect(row.encrypted_data).toEqual(Buffer.from(unb64(sent.ciphertext)));
      // Ciphertext-shaped: exactly plaintext length plus the 16-byte tag.
      expect(row.encrypted_data).toHaveLength(Buffer.byteLength(sent.plaintext) + 16);
      expect(row.revision).toBe(sent.revision);
      const binding = { itemId: row.id, revision: row.revision };
      expect(await decryptItem(row.encrypted_data, row.nonce, owner.vaultKey, binding)).toBe(
        sent.plaintext,
      );
      const otherKeys = [alice, bob, bobBefore].filter((user) => user !== owner);
      for (const other of otherKeys) {
        await expect(
          decryptItem(row.encrypted_data, row.nonce, other.vaultKey, binding),
        ).rejects.toThrow(DecryptionError);
      }
    }
  });

  it('sessions: stores only SHA-256 hashes of bearer tokens', async () => {
    const { rows } = await ctx.pool.query('SELECT * FROM sessions');
    expect(Object.keys(rows[0]).sort()).toEqual(
      [
        'client',
        'created_at',
        'expires_at',
        'id',
        'last_used_at',
        'token_hash',
        'user_agent',
        'user_id',
      ].sort(),
    );
    const allTokens = [...aliceTokens, ...bobTokens];
    expect(rows).toHaveLength(allTokens.length);
    const expectedHashes = allTokens
      .map((token) =>
        createHash('sha256').update(Buffer.from(token, 'base64url')).digest().toString('hex'),
      )
      .sort();
    expect(rows.map((row) => row.token_hash.toString('hex')).sort()).toEqual(expectedHashes);
  });

  it('API responses return ciphertext only', async () => {
    const responses = await Promise.all([
      ctx.app.inject({ method: 'GET', url: '/vault-items', headers: bearer(aliceTokens[0]!) }),
      ctx.app.inject({ method: 'GET', url: '/vault-key', headers: bearer(aliceTokens[0]!) }),
      ctx.app.inject({ method: 'POST', url: '/prelogin', payload: { email: alice.email } }),
    ]);
    const nonTokenSecrets = secrets.filter((secret) => !secret.name.includes('session token'));
    for (const response of responses) {
      expect(response.statusCode).toBe(200);
      for (const secret of nonTokenSecrets) {
        const text = typeof secret.value === 'string' ? secret.value : b64(secret.value);
        expect(response.body.includes(text), `${secret.name} in ${response.body}`).toBe(false);
      }
      expect(response.body).not.toMatch(/auth_hash/);
    }
  });
});

describe('the leak scanner itself', () => {
  it('detects a planted plaintext item, a raw authHash, and a base64-encoded password', async () => {
    const ctx = await createTestContext();
    try {
      const { user, token } = await registerAndLogin(
        ctx.app,
        'plant@example.com',
        'planted-MASTER-PASSWORD-0000',
      );
      const plaintext = JSON.stringify(item('planted'));
      const created = await createItem(ctx.app, token, user.vaultKey, plaintext);
      const secrets: Secret[] = [
        { name: 'item', value: plaintext },
        { name: 'raw authHash', value: user.authHash },
        { name: 'master password', value: user.password },
      ];
      expect(await scanDatabaseForSecrets(ctx.pool, secrets)).toEqual([]);

      // Simulate a buggy server that stored things it shouldn't.
      await ctx.pool.query(
        `UPDATE vault_items SET encrypted_data = convert_to($1, 'UTF8') WHERE id = $2`,
        [plaintext, created.id],
      );
      await ctx.pool.query('UPDATE users SET auth_hash = $1', [Buffer.from(user.authHash)]);
      await ctx.pool.query(
        `UPDATE users SET kdf_params = kdf_params || jsonb_build_object('debug', $1::text)`,
        [Buffer.from(user.password).toString('base64')],
      );

      expect(await scanDatabaseForSecrets(ctx.pool, secrets)).toEqual(
        expect.arrayContaining([
          { table: 'vault_items', column: 'encrypted_data', secret: 'item', encoding: 'raw' },
          { table: 'users', column: 'auth_hash', secret: 'raw authHash', encoding: 'raw' },
          { table: 'users', column: 'kdf_params', secret: 'master password', encoding: 'base64' },
        ]),
      );
    } finally {
      await ctx.close();
    }
  });
});
