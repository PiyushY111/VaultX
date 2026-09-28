import { copyFile, mkdtemp, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MIGRATIONS_DIR, migrate } from '../src/migrate.js';
import { rotateTotpKey } from '../src/rotate-totp-key.js';
import {
  findUnknownTotpKeyIds,
  prepareTotpSecrets,
  reencryptTotpSecrets,
} from '../src/totp-reencrypt.js';
import {
  ENCRYPTED_TOTP_SECRET_BYTES,
  decryptTotpSecret,
  encryptTotpSecret,
  parseTotpKeyring,
  type TotpKeyring,
} from '../src/totp-secret-box.js';
import { base32Encode } from '../src/totp.js';
import {
  TEST_TOTP_KEY,
  TEST_TOTP_OLD_KEY,
  b64,
  base32Decode,
  bearer,
  createClientUser,
  createTestContext,
  registerAndLogin,
  scanDatabaseForSecrets,
  signup,
  totpCode,
  type ClientUser,
  type TestContext,
} from './helpers.js';

const NEW_KEY = Buffer.alloc(32, 0x3c).toString('base64');

interface TotpRow {
  id: string;
  totp_secret: Buffer | null;
  totp_pending_secret: Buffer | null;
}

async function totpRow(ctx: TestContext, email: string): Promise<TotpRow> {
  const { rows } = await ctx.pool.query<TotpRow>(
    'SELECT id, totp_secret, totp_pending_secret FROM users WHERE email = $1',
    [email],
  );
  return rows[0]!;
}

async function startSetup(ctx: TestContext, token: string): Promise<string> {
  const response = await ctx.app.inject({
    method: 'POST',
    url: '/account/totp/setup',
    headers: bearer(token),
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json<{ secret: string }>().secret;
}

/** Turns on two-factor for a user; returns the base32 secret. */
async function enableTotp(ctx: TestContext, user: ClientUser, token: string): Promise<string> {
  const secret = await startSetup(ctx, token);
  const response = await ctx.app.inject({
    method: 'POST',
    url: '/account/totp/enable',
    headers: bearer(token),
    payload: { current_auth_hash: b64(user.authHash), totp_code: totpCode(secret) },
  });
  expect(response.statusCode, response.body).toBe(200);
  // Let the same code be used again for the login checks below.
  await ctx.pool.query('UPDATE users SET totp_last_step = 0 WHERE email = $1', [user.email]);
  return secret;
}

async function loginWithCode(ctx: TestContext, user: ClientUser, code: string) {
  return ctx.app.inject({
    method: 'POST',
    url: '/login',
    payload: { email: user.email, auth_hash: b64(user.authHash), totp_code: code },
  });
}

describe('two-factor secrets are encrypted at rest', () => {
  let ctx: TestContext;
  let keyring: TotpKeyring;

  beforeAll(async () => {
    ctx = await createTestContext();
    keyring = ctx.config.totpKeys;
  });

  afterAll(async () => {
    await ctx?.close();
  });

  it('stores the pending secret as ciphertext bound to the pending column', async () => {
    const { token } = await registerAndLogin(ctx.app, 'pending@example.com', 'pw-pending');
    const secret = await startSetup(ctx, token);
    const row = await totpRow(ctx, 'pending@example.com');
    expect(row.totp_secret).toBeNull();
    expect(row.totp_pending_secret).toHaveLength(ENCRYPTED_TOTP_SECRET_BYTES);
    expect(row.totp_pending_secret![0]).toBe(keyring.primary.id);
    expect(decryptTotpSecret(keyring, row.id, 'pending', row.totp_pending_secret!)).toEqual(
      base32Decode(secret),
    );
  });

  it('re-encrypts it for the active column on enable, and logins still work', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'active@example.com', 'pw-active');
    const secret = await enableTotp(ctx, user, token);
    const row = await totpRow(ctx, user.email);
    expect(row.totp_pending_secret).toBeNull();
    expect(row.totp_secret).toHaveLength(ENCRYPTED_TOTP_SECRET_BYTES);
    expect(decryptTotpSecret(keyring, row.id, 'active', row.totp_secret!)).toEqual(
      base32Decode(secret),
    );
    const response = await loginWithCode(ctx, user, totpCode(secret));
    expect(response.statusCode, response.body).toBe(200);
  });

  it('refuses a secret copied from another account (500, never a successful login)', async () => {
    const a = await registerAndLogin(ctx.app, 'copy-a@example.com', 'pw-copy-a');
    const b = await registerAndLogin(ctx.app, 'copy-b@example.com', 'pw-copy-b');
    await enableTotp(ctx, a.user, a.token);
    const bSecret = await enableTotp(ctx, b.user, b.token);
    // An attacker with database write access copies b's secret over a's, then
    // logs in as a with b's code.
    await ctx.pool.query(
      `UPDATE users SET totp_secret = (SELECT totp_secret FROM users WHERE email = $2)
       WHERE email = $1`,
      [a.user.email, b.user.email],
    );
    const response = await loginWithCode(ctx, a.user, totpCode(bSecret));
    expect(response.statusCode).toBe(500);
    expect(response.body).not.toContain(bSecret);
  });

  it('refuses a pending secret moved into the active column', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'promote@example.com', 'pw-promote');
    const secret = await startSetup(ctx, token);
    await ctx.pool.query(
      'UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL WHERE email = $1',
      [user.email],
    );
    expect((await loginWithCode(ctx, user, totpCode(secret))).statusCode).toBe(500);
  });

  it('keeps raw secrets out of the database', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'scan@example.com', 'pw-scan');
    const secret = await enableTotp(ctx, user, token);
    const raw = base32Decode(secret);
    const leaks = await scanDatabaseForSecrets(ctx.pool, [
      { name: 'raw secret', value: raw },
      { name: 'base32 secret', value: secret },
    ]);
    expect(leaks).toEqual([]);
  });
});

describe('legacy plaintext secrets (before migration 005)', () => {
  let ctx: TestContext;
  let user: ClientUser;
  let pendingUser: ClientUser;
  const activeSecret = Buffer.from('legacy-active-secret'); // 20 bytes
  const pendingSecret = Buffer.from('legacy-pendingsecret'); // 20 bytes

  beforeAll(async () => {
    ctx = await createTestContext({}, { migrations: false });
    // Build the pre-005 schema and fill it the way the old server did.
    const dir = await mkdtemp(join(tmpdir(), 'migrations-'));
    const before005 = (await readdir(MIGRATIONS_DIR)).filter((name) => name < '005');
    for (const name of before005) await copyFile(join(MIGRATIONS_DIR, name), join(dir, name));
    await migrate(ctx.pool, dir);

    user = await createClientUser('legacy@example.com', 'pw-legacy');
    pendingUser = await createClientUser('legacy-pending@example.com', 'pw-legacy-pending');
    for (const u of [user, pendingUser]) expect((await signup(ctx.app, u)).statusCode).toBe(201);
    await ctx.pool.query('UPDATE users SET totp_secret = $2 WHERE email = $1', [
      user.email,
      activeSecret,
    ]);
    await ctx.pool.query('UPDATE users SET totp_pending_secret = $2 WHERE email = $1', [
      pendingUser.email,
      pendingSecret,
    ]);

    expect(await migrate(ctx.pool)).toEqual(['005_encrypt_totp_secrets.sql', '006_webauthn.sql']);
  });

  afterAll(async () => {
    await ctx?.close();
  });

  it('migration 005 keeps the legacy values, and they still work until re-encrypted', async () => {
    expect((await totpRow(ctx, user.email)).totp_secret).toEqual(activeSecret);
    const code = totpCode(base32Encode(activeSecret));
    expect((await loginWithCode(ctx, user, code)).statusCode).toBe(200);
    await ctx.pool.query('UPDATE users SET totp_last_step = 0');
  });

  it('allows only the legacy and encrypted lengths', async () => {
    await expect(
      ctx.pool.query('UPDATE users SET totp_secret = $2 WHERE email = $1', [
        user.email,
        Buffer.alloc(32, 1),
      ]),
    ).rejects.toThrow(/users_totp_secret_check/);
    await expect(
      ctx.pool.query('UPDATE users SET totp_pending_secret = $2 WHERE email = $1', [
        user.email,
        Buffer.alloc(48, 1),
      ]),
    ).rejects.toThrow(/users_totp_pending_secret_check/);
  });

  it('startup encrypts them once, idempotently, even from several instances at once', async () => {
    const results = await Promise.all([
      prepareTotpSecrets(ctx.pool, ctx.config.totpKeys),
      prepareTotpSecrets(ctx.pool, ctx.config.totpKeys),
      prepareTotpSecrets(ctx.pool, ctx.config.totpKeys),
    ]);
    expect(results.reduce((sum, result) => sum + result.updated, 0)).toBe(2);
    expect(results.flatMap((result) => result.failed)).toEqual([]);
    expect((await prepareTotpSecrets(ctx.pool, ctx.config.totpKeys)).updated).toBe(0);

    const active = await totpRow(ctx, user.email);
    expect(active.totp_secret).toHaveLength(ENCRYPTED_TOTP_SECRET_BYTES);
    expect(
      decryptTotpSecret(ctx.config.totpKeys, active.id, 'active', active.totp_secret!),
    ).toEqual(activeSecret);
    const pending = await totpRow(ctx, pendingUser.email);
    expect(
      decryptTotpSecret(ctx.config.totpKeys, pending.id, 'pending', pending.totp_pending_secret!),
    ).toEqual(pendingSecret);

    expect(
      await scanDatabaseForSecrets(ctx.pool, [
        { name: 'legacy active', value: activeSecret },
        { name: 'legacy active (base32)', value: base32Encode(activeSecret) },
        { name: 'legacy pending', value: pendingSecret },
        { name: 'legacy pending (base32)', value: base32Encode(pendingSecret) },
      ]),
    ).toEqual([]);
  });

  it('logins keep working with the re-encrypted secret', async () => {
    const code = totpCode(base32Encode(activeSecret));
    expect((await loginWithCode(ctx, user, code)).statusCode).toBe(200);
  });
});

describe('key rotation', () => {
  let ctx: TestContext;
  let users: { user: ClientUser; secret: string }[];
  const lines: string[] = [];
  const log = { info: (m: string) => lines.push(m), error: (m: string) => lines.push(m) };

  beforeAll(async () => {
    // The server starts on the old key alone.
    ctx = await createTestContext({ totpKeys: parseTotpKeyring(TEST_TOTP_OLD_KEY) });
    users = [];
    for (const name of ['r1', 'r2', 'r3']) {
      const { user, token } = await registerAndLogin(ctx.app, `${name}@example.com`, `pw-${name}`);
      users.push({ user, secret: await enableTotp(ctx, user, token) });
    }
    const { token } = await registerAndLogin(ctx.app, 'r-pending@example.com', 'pw-rp');
    await startSetup(ctx, token);
  });

  afterAll(async () => {
    await ctx?.close();
  });

  it('re-encrypts every secret under the new primary key', async () => {
    const env = { TOTP_ENCRYPTION_KEY: `${NEW_KEY},${TEST_TOTP_OLD_KEY}` };
    expect(await rotateTotpKey(ctx.pool, env, log)).toBe(0);
    expect(lines.at(-1)).toMatch(/for 4 account\(s\)/);

    // Everything now opens with the new key alone.
    const newOnly = parseTotpKeyring(NEW_KEY);
    const { rows } = await ctx.pool.query<TotpRow>(
      'SELECT id, totp_secret, totp_pending_secret FROM users',
    );
    for (const row of rows) {
      if (row.totp_secret) decryptTotpSecret(newOnly, row.id, 'active', row.totp_secret);
      if (row.totp_pending_secret) {
        decryptTotpSecret(newOnly, row.id, 'pending', row.totp_pending_secret);
      }
    }
    expect(await findUnknownTotpKeyIds(ctx.pool, newOnly)).toEqual([]);
    // Re-running is a no-op.
    expect(await rotateTotpKey(ctx.pool, env, log)).toBe(0);
    expect(lines.at(-1)).toMatch(/for 0 account\(s\)/);
  });

  it('startup refuses to run when a stored secret uses a key that was removed', async () => {
    await expect(prepareTotpSecrets(ctx.pool, parseTotpKeyring(TEST_TOTP_KEY))).rejects.toThrow(
      /missing from TOTP_ENCRYPTION_KEY: key id \d+ \(4 account\(s\)\)/,
    );
  });

  it('reports accounts it cannot decrypt, rotates the rest, and exits non-zero', async () => {
    // Plant one secret under a key the rotation won't be given.
    const stray = parseTotpKeyring(TEST_TOTP_KEY);
    const { user } = users[0]!;
    const row = await totpRow(ctx, user.email);
    await ctx.pool.query('UPDATE users SET totp_secret = $2 WHERE id = $1', [
      row.id,
      encryptTotpSecret(stray, row.id, 'active', Buffer.alloc(20, 7)),
    ]);
    lines.length = 0;
    const env = { TOTP_ENCRYPTION_KEY: `${TEST_TOTP_OLD_KEY},${NEW_KEY}` };
    expect(await rotateTotpKey(ctx.pool, env, log)).toBe(1);
    expect(lines.join('\n')).toContain(row.id);
    expect(lines.join('\n')).toMatch(/1 account\(s\) could not be re-encrypted/);
    const result = await reencryptTotpSecrets(
      ctx.pool,
      parseTotpKeyring(env.TOTP_ENCRYPTION_KEY),
      'rotate',
    );
    expect(result.updated).toBe(0);
    expect(result.failed.map((f) => f.userId)).toEqual([row.id]);
  });

  it('refuses to run with a missing or malformed key', async () => {
    await expect(rotateTotpKey(ctx.pool, {}, log)).rejects.toThrow(/not set/);
    await expect(rotateTotpKey(ctx.pool, { TOTP_ENCRYPTION_KEY: 'x' }, log)).rejects.toThrow(
      /32 bytes/,
    );
  });
});
