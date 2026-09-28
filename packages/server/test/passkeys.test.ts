import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseWebAuthnConfig } from '../src/webauthn-config.js';
import {
  TEST_WEBAUTHN,
  b64,
  bearer,
  createTestContext,
  registerAndLogin,
  totpCode,
  type ClientUser,
  type TestContext,
} from './helpers.js';
import { SoftwareAuthenticator, type CeremonyOptions } from './software-authenticator.js';

const ORIGIN = TEST_WEBAUTHN.origins[0]!;
const GOOD: CeremonyOptions = { origin: ORIGIN };

let ctx: TestContext;
let counter = 0;

beforeAll(async () => {
  ctx = await createTestContext();
});

afterAll(async () => {
  await ctx?.close();
});

interface Account {
  user: ClientUser;
  token: string;
  key: SoftwareAuthenticator;
  recoveryCodes: string[];
  passkeyId: string;
}

const reauth = (user: ClientUser, extra: Record<string, unknown> = {}) => ({
  current_auth_hash: b64(user.authHash),
  ...extra,
});

async function registerOptions(
  token: string,
  body: Record<string, unknown>,
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const response = await ctx.app.inject({
    method: 'POST',
    url: '/account/passkeys/register/options',
    headers: bearer(token),
    payload: body,
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json().options;
}

async function finishRegistration(token: string, response: unknown, name = 'Test key') {
  return ctx.app.inject({
    method: 'POST',
    url: '/account/passkeys',
    headers: bearer(token),
    payload: { name, response },
  });
}

async function reauthOptions(token: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const response = await ctx.app.inject({
    method: 'POST',
    url: '/account/passkeys/reauth-options',
    headers: bearer(token),
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json().options;
}

/** A new account with one passkey (its first second factor). */
async function accountWithPasskey(key = new SoftwareAuthenticator()): Promise<Account> {
  const { user, token } = await registerAndLogin(
    ctx.app,
    `passkey-${++counter}@example.com`,
    `pw-passkey-${counter}`,
  );
  const options = await registerOptions(token, reauth(user));
  const finish = await finishRegistration(token, key.register(options, GOOD));
  expect(finish.statusCode, finish.body).toBe(201);
  const body = finish.json<{ passkey: { id: string }; recovery_codes: string[] }>();
  return { user, token, key, recoveryCodes: body.recovery_codes, passkeyId: body.passkey.id };
}

async function login(user: ClientUser, factor: Record<string, unknown> = {}) {
  return ctx.app.inject({
    method: 'POST',
    url: '/login',
    payload: { email: user.email, auth_hash: b64(user.authHash), ...factor },
  });
}

/** Asks for the second factor, and returns the passkey options it came with. */
async function loginOptions(user: ClientUser): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const response = await login(user);
  expect(response.statusCode).toBe(401);
  return response.json().webauthn_options;
}

async function expireChallenges(user: ClientUser) {
  await ctx.pool.query(
    `UPDATE webauthn_challenges SET expires_at = now() - interval '1 second'
     WHERE user_id = (SELECT id FROM users WHERE email = $1)`,
    [user.email],
  );
}

async function resetThrottle() {
  await ctx.pool.query('DELETE FROM login_failures');
}

describe('WEBAUTHN_* configuration', () => {
  const valid = { WEBAUTHN_RP_ID: 'example.com', WEBAUTHN_ORIGINS: 'https://vault.example.com' };

  it('accepts a domain and origins on it or its subdomains', () => {
    expect(
      parseWebAuthnConfig({
        ...valid,
        WEBAUTHN_ORIGINS: 'https://example.com, https://vault.example.com:8443',
      }),
    ).toEqual({
      rpId: 'example.com',
      rpName: 'VaultX',
      origins: ['https://example.com', 'https://vault.example.com:8443'],
    });
    expect(
      parseWebAuthnConfig({
        WEBAUTHN_RP_ID: 'localhost',
        WEBAUTHN_ORIGINS: 'http://localhost:5173',
        WEBAUTHN_RP_NAME: 'My vault',
      }).rpName,
    ).toBe('My vault');
  });

  it.each([
    [{ WEBAUTHN_RP_ID: '' }, /WEBAUTHN_RP_ID is not set/],
    [{ WEBAUTHN_RP_ID: 'https://example.com' }, /lowercase domain/],
    [{ WEBAUTHN_RP_ID: 'Example.com' }, /lowercase domain/],
    [{ WEBAUTHN_RP_ID: 'example.com:443' }, /lowercase domain/],
    [{ WEBAUTHN_RP_ID: '127.0.0.1', WEBAUTHN_ORIGINS: 'http://127.0.0.1' }, /lowercase domain/],
    [{ WEBAUTHN_ORIGINS: '' }, /WEBAUTHN_ORIGINS is not set/],
    [{ WEBAUTHN_ORIGINS: 'vault.example.com' }, /not a URL/],
    [{ WEBAUTHN_ORIGINS: 'https://vault.example.com/' }, /origin only/],
    [{ WEBAUTHN_ORIGINS: 'https://vault.example.com/app' }, /origin only/],
    [{ WEBAUTHN_ORIGINS: 'http://vault.example.com' }, /must use https/],
    [{ WEBAUTHN_ORIGINS: 'https://example.org' }, /not on WEBAUTHN_RP_ID/],
    [{ WEBAUTHN_ORIGINS: 'https://notexample.com' }, /not on WEBAUTHN_RP_ID/],
    [{ WEBAUTHN_RP_NAME: 'x'.repeat(65) }, /at most 64/],
  ])('rejects %o', (override, message) => {
    expect(() => parseWebAuthnConfig({ ...valid, ...override })).toThrow(message);
  });
});

describe('registering a passkey', () => {
  it('stores the public key, and gives the first second factor recovery codes', async () => {
    const account = await accountWithPasskey();
    expect(account.recoveryCodes).toHaveLength(10);
    const list = await ctx.app.inject({
      method: 'GET',
      url: '/account/passkeys',
      headers: bearer(account.token),
    });
    expect(list.json().passkeys).toEqual([
      expect.objectContaining({
        id: account.passkeyId,
        name: 'Test key',
        transports: ['internal'],
      }),
    ]);
    expect(Object.keys(list.json().passkeys[0]).sort()).toEqual(
      ['created_at', 'id', 'last_used_at', 'name', 'transports'].sort(),
    );
    const info = await ctx.app.inject({
      method: 'GET',
      url: '/account',
      headers: bearer(account.token),
    });
    expect(info.json()).toMatchObject({
      totp_enabled: false,
      passkeys: 1,
      passkey_required: false,
      recovery_codes_remaining: 10,
    });
  });

  it('needs the master password to begin', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'reg-pw@example.com', 'pw-reg-pw');
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/account/passkeys/register/options',
      headers: bearer(token),
      payload: { current_auth_hash: b64(new Uint8Array(32)) },
    });
    expect(response.statusCode).toBe(403);
    expect(response.json()).not.toHaveProperty('webauthn_options');
    expect(user).toBeDefined();
  });

  it('needs an existing second factor to add another, and keeps the recovery codes', async () => {
    const account = await accountWithPasskey();
    const withoutFactor = await ctx.app.inject({
      method: 'POST',
      url: '/account/passkeys/register/options',
      headers: bearer(account.token),
      payload: reauth(account.user),
    });
    expect(withoutFactor.statusCode).toBe(403);
    expect(withoutFactor.json()).toMatchObject({
      totp_required: true,
      second_factor_methods: ['webauthn', 'recovery_code'],
    });

    const assertion = account.key.authenticate(await reauthOptions(account.token), GOOD);
    const options = await registerOptions(
      account.token,
      reauth(account.user, { webauthn: assertion }),
    );
    const second = new SoftwareAuthenticator();
    const finish = await finishRegistration(
      account.token,
      second.register(options, GOOD),
      'Backup',
    );
    expect(finish.statusCode, finish.body).toBe(201);
    expect(finish.json()).not.toHaveProperty('recovery_codes');
    // The existing passkey is excluded, so the browser won't register it twice.
    expect(options.excludeCredentials?.map((c) => c.id)).toEqual([
      account.key.credentialId.toString('base64url'),
    ]);
  });

  it.each<[string, CeremonyOptions]>([
    ['from the wrong origin', { origin: 'https://evil.test' }],
    ['for the wrong RP ID', { origin: ORIGIN, rpId: 'evil.test' }],
    ['without user verification', { origin: ORIGIN, userVerified: false }],
  ])('refuses a registration %s', async (_, ceremony) => {
    const { user, token } = await registerAndLogin(
      ctx.app,
      `reg-bad-${++counter}@example.com`,
      'pw-reg-bad',
    );
    const options = await registerOptions(token, reauth(user));
    const finish = await finishRegistration(
      token,
      new SoftwareAuthenticator().register(options, ceremony),
    );
    expect(finish.statusCode).toBe(400);
    const { rows } = await ctx.pool.query(
      'SELECT 1 FROM webauthn_credentials WHERE user_id = (SELECT id FROM users WHERE email = $1)',
      [user.email],
    );
    expect(rows).toEqual([]);
  });

  it('refuses an expired, replayed, or another user’s registration challenge', async () => {
    const a = await registerAndLogin(ctx.app, 'reg-chal-a@example.com', 'pw-reg-chal-a');
    const b = await registerAndLogin(ctx.app, 'reg-chal-b@example.com', 'pw-reg-chal-b');

    // Expired.
    const expiredOptions = await registerOptions(a.token, reauth(a.user));
    await expireChallenges(a.user);
    const key = new SoftwareAuthenticator();
    expect((await finishRegistration(a.token, key.register(expiredOptions, GOOD))).statusCode).toBe(
      400,
    );

    // Another user's challenge: B finishes with a response to A's options.
    const aOptions = await registerOptions(a.token, reauth(a.user));
    expect((await finishRegistration(b.token, key.register(aOptions, GOOD))).statusCode).toBe(400);

    // Single use: the first finish succeeds; replaying it (with a fresh
    // credential id, so uniqueness doesn't mask it) fails.
    const response = key.register(aOptions, GOOD);
    expect((await finishRegistration(a.token, response)).statusCode).toBe(201);
    const other = new SoftwareAuthenticator();
    const replay = other.register(aOptions, GOOD);
    expect((await finishRegistration(a.token, replay)).statusCode).toBe(400);
  });

  it('won’t register one credential to two accounts', async () => {
    const shared = new SoftwareAuthenticator();
    await accountWithPasskey(shared);
    const { user, token } = await registerAndLogin(ctx.app, 'dup@example.com', 'pw-dup');
    const options = await registerOptions(token, reauth(user));
    const finish = await finishRegistration(token, shared.register(options, GOOD));
    expect(finish.statusCode).toBe(409);
  });

  it('refuses blank names and bad response shapes', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'shape@example.com', 'pw-shape');
    const options = await registerOptions(token, reauth(user));
    const response = new SoftwareAuthenticator().register(options, GOOD);
    expect((await finishRegistration(token, response, '   ')).statusCode).toBe(400);
    expect((await finishRegistration(token, { ...response, type: 'password' })).statusCode).toBe(
      400,
    );
    expect((await finishRegistration(token, { ...response, extra: 'field' })).statusCode).toBe(400);
  });
});

describe('logging in with a passkey', () => {
  it('asks for the second factor only after the password, with passkey options', async () => {
    const account = await accountWithPasskey();
    const wrongPassword = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: account.user.email, auth_hash: b64(new Uint8Array(32)) },
    });
    expect(wrongPassword.statusCode).toBe(401);
    expect(Object.keys(wrongPassword.json()).sort()).toEqual(
      ['attempts_remaining', 'error', 'message', 'statusCode'].sort(),
    );

    const response = await login(account.user);
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({
      totp_required: true,
      second_factor_methods: ['webauthn', 'recovery_code'],
      message: 'Use your passkey, or one of your recovery codes.',
    });
    const options: PublicKeyCredentialRequestOptionsJSON = response.json().webauthn_options;
    expect(options.rpId).toBe(TEST_WEBAUTHN.rpId);
    expect(options.userVerification).toBe('required');
    expect(options.allowCredentials?.map((c) => c.id)).toEqual([
      account.key.credentialId.toString('base64url'),
    ]);

    const ok = await login(account.user, {
      webauthn: account.key.authenticate(options, GOOD),
      client: 'web',
    });
    expect(ok.statusCode, ok.body).toBe(200);
    const { rows } = await ctx.pool.query(
      'SELECT last_used_at FROM webauthn_credentials WHERE id = $1',
      [account.passkeyId],
    );
    expect(rows[0].last_used_at).not.toBeNull();
  });

  it('refuses a replayed assertion', async () => {
    const account = await accountWithPasskey();
    const assertion = account.key.authenticate(await loginOptions(account.user), GOOD);
    expect((await login(account.user, { webauthn: assertion })).statusCode).toBe(200);
    const replay = await login(account.user, { webauthn: assertion });
    expect(replay.statusCode).toBe(401);
    expect(replay.json().message).toMatch(/passkey wasn’t accepted/);
  });

  it.each<[string, CeremonyOptions]>([
    ['from the wrong origin', { origin: 'https://evil.test' }],
    ['from a lookalike origin', { origin: 'https://vault.test.evil.test' }],
    ['for the wrong RP ID', { origin: ORIGIN, rpId: 'evil.test' }],
    ['without user verification', { origin: ORIGIN, userVerified: false }],
  ])('refuses an assertion %s', async (_, ceremony) => {
    const account = await accountWithPasskey();
    const options = await loginOptions(account.user);
    const response = await login(account.user, {
      webauthn: account.key.authenticate(options, ceremony),
    });
    expect(response.statusCode).toBe(401);
    // A fresh challenge comes back for the next try.
    expect(response.json().webauthn_options.challenge).not.toBe(options.challenge);
  });

  it('refuses an expired challenge', async () => {
    const account = await accountWithPasskey();
    const options = await loginOptions(account.user);
    await expireChallenges(account.user);
    const response = await login(account.user, {
      webauthn: account.key.authenticate(options, GOOD),
    });
    expect(response.statusCode).toBe(401);
  });

  it('refuses a challenge issued for re-authentication', async () => {
    const account = await accountWithPasskey();
    const options = await reauthOptions(account.token);
    const response = await login(account.user, {
      webauthn: account.key.authenticate(options, GOOD),
    });
    expect(response.statusCode).toBe(401);
  });

  it('refuses another account’s passkey, even signing this account’s challenge', async () => {
    const alice = await accountWithPasskey();
    const bob = await accountWithPasskey();
    const options = await loginOptions(alice.user);
    const response = await login(alice.user, { webauthn: bob.key.authenticate(options, GOOD) });
    expect(response.statusCode).toBe(401);
    // And Bob's own challenge can't be spent on Alice's login.
    const bobOptions = await loginOptions(bob.user);
    expect(
      (await login(alice.user, { webauthn: alice.key.authenticate(bobOptions, GOOD) })).statusCode,
    ).toBe(401);
  });

  it('refuses a signature counter that goes backwards, or stays the same', async () => {
    const key = new SoftwareAuthenticator();
    key.counter = 5;
    const account = await accountWithPasskey(key);
    const next = key.authenticate(await loginOptions(account.user), GOOD); // counter 6
    expect((await login(account.user, { webauthn: next })).statusCode).toBe(200);

    for (const stale of [3, 6]) {
      const response = await login(account.user, {
        webauthn: key.authenticate(await loginOptions(account.user), GOOD, { counter: stale }),
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().message).toMatch(/counter went backwards/);
    }
    const { rows } = await ctx.pool.query(
      'SELECT sign_counter FROM webauthn_credentials WHERE id = $1',
      [account.passkeyId],
    );
    expect(Number(rows[0].sign_counter)).toBe(6);
    // Moving forward again works.
    const forward = key.authenticate(await loginOptions(account.user), GOOD, { counter: 10 });
    expect((await login(account.user, { webauthn: forward })).statusCode).toBe(200);
  });

  it('accepts passkeys that always report a zero counter', async () => {
    const account = await accountWithPasskey(); // counter stays 0
    for (let i = 0; i < 2; i++) {
      const assertion = account.key.authenticate(await loginOptions(account.user), GOOD);
      expect((await login(account.user, { webauthn: assertion })).statusCode).toBe(200);
    }
  });

  it('counts refused passkeys toward the per-account lockout', async () => {
    await resetThrottle();
    const account = await accountWithPasskey();
    const bad = await login(account.user, {
      webauthn: account.key.authenticate(await loginOptions(account.user), {
        origin: 'https://evil.test',
      }),
    });
    expect(bad.json().attempts_remaining).toBe(4);
    await resetThrottle();
  });

  it('keeps recovery codes working, each once', async () => {
    const account = await accountWithPasskey();
    const code = account.recoveryCodes[0]!;
    expect((await login(account.user, { recovery_code: code })).statusCode).toBe(200);
    expect((await login(account.user, { recovery_code: code })).statusCode).toBe(401);
  });

  it('offers TOTP alongside passkeys when both are on', async () => {
    const account = await accountWithPasskey();
    const secret = await enableTotp(account);
    const response = await login(account.user);
    expect(response.json().second_factor_methods).toEqual(['webauthn', 'totp', 'recovery_code']);
    expect((await login(account.user, { totp_code: totpCode(secret) })).statusCode).toBe(200);
  });
});

/** Turns on TOTP for an account that already has a passkey (which that takes). */
async function enableTotp(account: Account): Promise<string> {
  // Turning TOTP on issues a fresh set of recovery codes, replacing the old.
  const setup = await ctx.app.inject({
    method: 'POST',
    url: '/account/totp/setup',
    headers: bearer(account.token),
  });
  const secret: string = setup.json().secret;
  const withoutFactor = await ctx.app.inject({
    method: 'POST',
    url: '/account/totp/enable',
    headers: bearer(account.token),
    payload: reauth(account.user, { totp_code: totpCode(secret) }),
  });
  expect(withoutFactor.statusCode).toBe(403);
  const enable = await ctx.app.inject({
    method: 'POST',
    url: '/account/totp/enable',
    headers: bearer(account.token),
    payload: reauth(account.user, {
      totp_code: totpCode(secret),
      webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
    }),
  });
  expect(enable.statusCode, enable.body).toBe(200);
  account.recoveryCodes = enable.json().recovery_codes;
  await ctx.pool.query('UPDATE users SET totp_last_step = 0 WHERE email = $1', [
    account.user.email,
  ]);
  return secret;
}

async function setRequired(account: Account, required: boolean, factor: Record<string, unknown>) {
  return ctx.app.inject({
    method: 'PUT',
    url: '/account/passkeys/required',
    headers: bearer(account.token),
    payload: reauth(account.user, { required, ...factor }),
  });
}

describe('require passkey', () => {
  it('stops TOTP codes counting for login and re-authentication; recovery codes still work', async () => {
    const account = await accountWithPasskey();
    const secret = await enableTotp(account);
    const on = await setRequired(account, true, { totp_code: totpCode(secret) });
    expect(on.statusCode, on.body).toBe(204);
    await ctx.pool.query('UPDATE users SET totp_last_step = 0 WHERE email = $1', [
      account.user.email,
    ]);

    const prompt = await login(account.user);
    expect(prompt.json().second_factor_methods).toEqual(['webauthn', 'recovery_code']);
    const totp = await login(account.user, { totp_code: totpCode(secret) });
    expect(totp.statusCode).toBe(401);
    expect(totp.json().message).toMatch(/requires a passkey/);

    // Re-authentication won't take TOTP either: turning it back off needs the passkey.
    expect((await setRequired(account, false, { totp_code: totpCode(secret) })).statusCode).toBe(
      403,
    );
    expect(
      (await login(account.user, { recovery_code: account.recoveryCodes[0]! })).statusCode,
    ).toBe(200);
    const off = await setRequired(account, false, {
      webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
    });
    expect(off.statusCode, off.body).toBe(204);
    await resetThrottle();
  });

  it('can’t be turned on without a passkey', async () => {
    const { user, token } = await registerAndLogin(ctx.app, 'req-none@example.com', 'pw-req-none');
    const response = await ctx.app.inject({
      method: 'PUT',
      url: '/account/passkeys/required',
      headers: bearer(token),
      payload: reauth(user, { required: true }),
    });
    expect(response.statusCode).toBe(409);
  });
});

async function deletePasskey(account: Account, id: string, factor: Record<string, unknown>) {
  return ctx.app.inject({
    method: 'DELETE',
    url: `/account/passkeys/${id}`,
    headers: bearer(account.token),
    payload: reauth(account.user, factor),
  });
}

describe('managing passkeys', () => {
  it('renames only your own passkeys', async () => {
    const alice = await accountWithPasskey();
    const bob = await accountWithPasskey();
    const rename = (token: string, id: string, name: string) =>
      ctx.app.inject({
        method: 'PATCH',
        url: `/account/passkeys/${id}`,
        headers: bearer(token),
        payload: { name },
      });
    const ok = await rename(alice.token, alice.passkeyId, '  Laptop  ');
    expect(ok.statusCode).toBe(200);
    expect(ok.json().passkey.name).toBe('Laptop');
    expect((await rename(bob.token, alice.passkeyId, 'Mine now')).statusCode).toBe(404);
  });

  it('deletes the last passkey only with re-authentication, turning two-factor off', async () => {
    const account = await accountWithPasskey();
    expect((await deletePasskey(account, account.passkeyId, {})).statusCode).toBe(403);
    const wrongPassword = await ctx.app.inject({
      method: 'DELETE',
      url: `/account/passkeys/${account.passkeyId}`,
      headers: bearer(account.token),
      payload: {
        current_auth_hash: b64(new Uint8Array(32)),
        webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
      },
    });
    expect(wrongPassword.statusCode).toBe(403);

    const removed = await deletePasskey(account, account.passkeyId, {
      webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
    });
    expect(removed.statusCode, removed.body).toBe(204);
    // No second factor left: the recovery codes are gone, and login needs only the password.
    const { rows } = await ctx.pool.query(
      'SELECT 1 FROM totp_recovery_codes WHERE user_id = (SELECT id FROM users WHERE email = $1)',
      [account.user.email],
    );
    expect(rows).toEqual([]);
    expect((await login(account.user)).statusCode).toBe(200);
    await resetThrottle();
  });

  it('keeps recovery codes when another factor remains', async () => {
    const account = await accountWithPasskey();
    await enableTotp(account);
    const removed = await deletePasskey(account, account.passkeyId, {
      recovery_code: account.recoveryCodes[0],
    });
    expect(removed.statusCode, removed.body).toBe(204);
    const info = await ctx.app.inject({
      method: 'GET',
      url: '/account',
      headers: bearer(account.token),
    });
    // TOTP enable issued a fresh set of ten, one of which was then used here.
    expect(info.json()).toMatchObject({ passkeys: 0, totp_enabled: true });
    expect(info.json().recovery_codes_remaining).toBeGreaterThan(0);
  });

  it('won’t delete another account’s passkey', async () => {
    const alice = await accountWithPasskey();
    const bob = await accountWithPasskey();
    const response = await deletePasskey(bob, alice.passkeyId, {
      webauthn: bob.key.authenticate(await reauthOptions(bob.token), GOOD),
    });
    expect(response.statusCode).toBe(404);
    const { rows } = await ctx.pool.query('SELECT 1 FROM webauthn_credentials WHERE id = $1', [
      alice.passkeyId,
    ]);
    expect(rows).toHaveLength(1);
  });

  it('won’t delete the only passkey while "require passkey" is on', async () => {
    const account = await accountWithPasskey();
    const on = await setRequired(account, true, {
      webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
    });
    expect(on.statusCode).toBe(204);
    const response = await deletePasskey(account, account.passkeyId, {
      webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
    });
    expect(response.statusCode).toBe(409);
  });

  it('turning TOTP off keeps the recovery codes that back up passkeys', async () => {
    const account = await accountWithPasskey();
    const secret = await enableTotp(account);
    const disable = await ctx.app.inject({
      method: 'POST',
      url: '/account/totp/disable',
      headers: bearer(account.token),
      payload: reauth(account.user, { totp_code: totpCode(secret) }),
    });
    expect(disable.statusCode, disable.body).toBe(204);
    const info = await ctx.app.inject({
      method: 'GET',
      url: '/account',
      headers: bearer(account.token),
    });
    expect(info.json()).toMatchObject({
      totp_enabled: false,
      passkeys: 1,
      recovery_codes_remaining: 10,
    });
  });

  it('deleting the account removes its passkeys and challenges', async () => {
    const account = await accountWithPasskey();
    await loginOptions(account.user); // leaves an open challenge
    const response = await ctx.app.inject({
      method: 'DELETE',
      url: '/account',
      headers: bearer(account.token),
      payload: reauth(account.user, {
        webauthn: account.key.authenticate(await reauthOptions(account.token), GOOD),
      }),
    });
    expect(response.statusCode, response.body).toBe(204);
    const { rows } = await ctx.pool.query(
      `SELECT (SELECT count(*)::int FROM webauthn_credentials WHERE id = $1) AS credentials`,
      [account.passkeyId],
    );
    expect(rows[0].credentials).toBe(0);
  });

  it('caps open challenges per user and purpose', async () => {
    const account = await accountWithPasskey();
    for (let i = 0; i < 8; i++) await loginOptions(account.user);
    const { rows } = await ctx.pool.query(
      `SELECT count(*)::int AS open FROM webauthn_challenges
       WHERE user_id = (SELECT id FROM users WHERE email = $1) AND purpose = 'login'`,
      [account.user.email],
    );
    expect(rows[0].open).toBe(5);
  });
});
