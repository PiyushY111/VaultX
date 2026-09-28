import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decodeBytes } from '../src/encoding.js';
import { HttpError } from '../src/http-errors.js';
import {
  PLACEHOLDER_MANIFEST,
  b64,
  bearer,
  createClientUser,
  createTestContext,
  registerAndLogin,
  signupPayload,
  type TestContext,
} from './helpers.js';
import { FUZZ_RUNS, Rng, expectTyped, forEachCase, mutate } from './fuzz.js';

/**
 * Seeded randomized tests for the server's input handling: decodeBytes on its
 * own, and every route's schema and handler with random and mutated
 * requests. Nothing may produce a 5xx (an unhandled error), a non-JSON
 * reply, or a slow reply. Reproduce a failure with the FUZZ_SEED it prints.
 */

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

describe('decodeBytes', () => {
  it('returns exactly the allowed length or throws a 400, for any string', async () => {
    await forEachCase('decodeBytes', async (rng) => {
      const value = rng.bool(0.7) ? rng.string(80, BASE64_CHARS) : rng.string(80);
      const rule = rng.bool()
        ? { exact: rng.int(64) }
        : (() => {
            const min = rng.int(40);
            return { min, max: min + rng.int(40) };
          })();
      const result = await expectTyped(() => decodeBytes(value, 'field', rule), [HttpError], {
        value,
        rule,
      });
      if (result.ok) {
        const { length } = result.value;
        if ('exact' in rule) expect(length).toBe(rule.exact);
        else expect(length >= rule.min && length <= rule.max).toBe(true);
      } else {
        expect((result.error as HttpError).statusCode).toBe(400);
      }
    });
  });
});

/** Replaces, deletes, adds or retypes one part of a JSON value. */
function mutateValue(rng: Rng, value: unknown, depth = 0): unknown {
  if (depth > 4 || value === null || typeof value !== 'object') {
    if (typeof value === 'string' && rng.bool(0.5)) return mutate(rng, value);
    return rng.json(2);
  }
  if (Array.isArray(value)) {
    const copy = [...value];
    if (copy.length && rng.bool(0.7)) {
      const at = rng.int(copy.length);
      copy[at] = mutateValue(rng, copy[at], depth + 1);
    } else copy.push(rng.json(2));
    return rng.bool(0.1) ? Array.from({ length: 600 }, () => copy[0]) : copy;
  }
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  const keys = Object.keys(copy);
  switch (rng.int(4)) {
    case 0:
      if (keys.length) delete copy[rng.pick(keys)];
      break;
    case 1:
      copy[rng.pick(['extra', '__proto__', 'constructor', rng.string(6)])] = rng.json(2);
      break;
    default:
      if (keys.length) {
        const key = rng.pick(keys);
        copy[key] = mutateValue(rng, copy[key], depth + 1);
      }
  }
  return copy;
}

describe('every route, with random and mutated requests', () => {
  let ctx: TestContext;
  let token: string;
  let routes: { method: string; url: () => string; body?: unknown; auth: boolean }[];

  beforeAll(async () => {
    ctx = await createTestContext();
    const account = await registerAndLogin(ctx.app, 'fuzz@example.com', 'pw-fuzz-account');
    token = account.token;
    const authHash = b64(account.user.authHash);
    const fresh = await createClientUser('fuzz-signup@example.com', 'pw-fuzz-signup');
    const item = {
      id: randomUUID(),
      revision: 1,
      encrypted_data: b64(new Uint8Array(40).fill(1)),
      nonce: b64(new Uint8Array(24).fill(2)),
      manifest: PLACEHOLDER_MANIFEST,
    };
    const assertion = {
      id: 'AAAA',
      rawId: 'AAAA',
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA' },
    };
    const reauth = { current_auth_hash: authHash, totp_code: '123456' };
    const id = () => randomUUID();
    // Everything except the requests that would end the fuzzing session (logout, sign out everywhere).
    routes = [
      { method: 'POST', url: () => '/signup', body: signupPayload(fresh), auth: false },
      { method: 'POST', url: () => '/prelogin', body: { email: 'fuzz@example.com' }, auth: false },
      {
        method: 'POST',
        url: () => '/login',
        body: { email: 'fuzz@example.com', auth_hash: authHash, webauthn: assertion },
        auth: false,
      },
      { method: 'GET', url: () => '/vault-items', auth: true },
      { method: 'GET', url: () => '/vault-key', auth: true },
      { method: 'POST', url: () => '/vault-items', body: item, auth: true },
      {
        method: 'POST',
        url: () => '/vault-items/batch',
        body: { items: [item], manifest: PLACEHOLDER_MANIFEST },
        auth: true,
      },
      { method: 'PUT', url: () => `/vault-items/${id()}`, body: item, auth: true },
      {
        method: 'DELETE',
        url: () => `/vault-items/${id()}`,
        body: { manifest: PLACEHOLDER_MANIFEST },
        auth: true,
      },
      { method: 'PUT', url: () => '/vault-manifest', body: PLACEHOLDER_MANIFEST, auth: true },
      {
        method: 'POST',
        url: () => '/account/password',
        body: {
          current_auth_hash: authHash,
          auth_hash: authHash,
          kdf_salt: b64(new Uint8Array(16)),
          kdf_params: { memoryCost: 19456, iterations: 2, parallelism: 1 },
          encrypted_vault_key: b64(new Uint8Array(48)),
          vault_key_nonce: b64(new Uint8Array(24)),
          items: [],
          manifest: PLACEHOLDER_MANIFEST,
        },
        auth: true,
      },
      { method: 'GET', url: () => '/account', auth: true },
      { method: 'GET', url: () => '/sessions', auth: true },
      { method: 'DELETE', url: () => `/sessions/${id()}`, auth: true },
      { method: 'POST', url: () => '/account/totp/setup', auth: true },
      { method: 'POST', url: () => '/account/totp/enable', body: reauth, auth: true },
      { method: 'POST', url: () => '/account/totp/disable', body: reauth, auth: true },
      { method: 'POST', url: () => '/account/totp/recovery-codes', body: reauth, auth: true },
      { method: 'POST', url: () => '/account/passkeys/register/options', body: reauth, auth: true },
      {
        method: 'POST',
        url: () => '/account/passkeys',
        body: {
          name: 'key',
          response: { ...assertion, response: { clientDataJSON: 'e30', attestationObject: 'oA' } },
        },
        auth: true,
      },
      { method: 'GET', url: () => '/account/passkeys', auth: true },
      { method: 'PATCH', url: () => `/account/passkeys/${id()}`, body: { name: 'x' }, auth: true },
      {
        method: 'DELETE',
        url: () => `/account/passkeys/${id()}`,
        body: { ...reauth, webauthn: assertion },
        auth: true,
      },
      { method: 'POST', url: () => '/account/passkeys/reauth-options', auth: true },
      {
        method: 'PUT',
        url: () => '/account/passkeys/required',
        body: { ...reauth, required: true },
        auth: true,
      },
      // A wrong password: with the real one this would (rightly) delete the fuzzing account.
      {
        method: 'DELETE',
        url: () => '/account',
        body: { ...reauth, current_auth_hash: b64(new Uint8Array(32)) },
        auth: true,
      },
    ];
  });

  afterAll(async () => {
    await ctx?.close();
  });

  it('never answers with a 5xx, a non-JSON body, or slowly', async () => {
    await forEachCase(
      'routes',
      async (rng) => {
        const route = rng.pick(routes);
        let url = route.url();
        if (rng.bool(0.1)) url = `${url.replace(/[0-9a-f-]{36}$/, '')}${rng.string(40)}`;
        const kind = rng.int(10);
        let payload: string | undefined;
        let contentType = 'application/json';
        if (kind === 0)
          payload = rng.string(200); // not JSON at all
        else if (kind === 1) payload = JSON.stringify(rng.json());
        else if (kind === 2 && route.body) payload = mutate(rng, JSON.stringify(route.body));
        else if (kind === 3)
          contentType = rng.pick(['text/plain', 'application/x-www-form-urlencoded', '']);
        else if (route.body) payload = JSON.stringify(mutateValue(rng, route.body));
        if (kind === 3) payload = route.body ? JSON.stringify(route.body) : undefined;

        const headers: Record<string, string> = {
          ...(route.auth && rng.bool(0.95) ? bearer(token) : {}),
          ...(payload !== undefined && contentType && { 'content-type': contentType }),
        };
        const started = performance.now();
        const response = await ctx.app.inject({
          method: route.method as 'GET',
          url,
          headers,
          ...(payload !== undefined && { payload }),
        });
        const elapsed = performance.now() - started;
        const detail = `${route.method} ${url} ${payload?.slice(0, 300)}`;
        expect(response.statusCode, `${detail}\n→ ${response.body.slice(0, 300)}`).toBeLessThan(
          500,
        );
        expect(elapsed, detail).toBeLessThan(2000);
        if (response.statusCode !== 204) {
          expect(() => JSON.parse(response.body), detail).not.toThrow();
        }
        // The fuzzing account must survive (no request here can legitimately delete it).
        if (response.statusCode === 401 && route.auth && headers.authorization) {
          const check = await ctx.app.inject({
            method: 'GET',
            url: '/account',
            headers: bearer(token),
          });
          expect(check.statusCode, `session lost after ${detail}`).toBe(200);
        }
      },
      FUZZ_RUNS * 3,
    );
  });
});
