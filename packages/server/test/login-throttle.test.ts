import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  b64,
  createClientUser,
  createTestContext,
  signup,
  type ClientUser,
  type TestContext,
} from './helpers.js';

let ctx: TestContext;
let counter = 0;

beforeAll(async () => {
  ctx = await createTestContext({ loginThrottle: { maxFailures: 3, windowSeconds: 600 } });
});

afterAll(async () => {
  await ctx?.close();
});

async function newUser(): Promise<ClientUser> {
  const user = await createClientUser(
    `throttle-${++counter}@example.com`,
    `pw-throttle-${counter}`,
  );
  expect((await signup(ctx.app, user)).statusCode).toBe(201);
  return user;
}

const WRONG_HASH = b64(new Uint8Array(32).fill(9));
const attempt = (email: string, authHash: string) =>
  ctx.app.inject({ method: 'POST', url: '/login', payload: { email, auth_hash: authHash } });

describe('per-account login throttling', () => {
  it('counts down remaining attempts, then refuses with 429, Retry-After and a clear message', async () => {
    const user = await newUser();
    const responses = [];
    for (let i = 0; i < 4; i++) responses.push(await attempt(user.email, WRONG_HASH));

    expect(responses.map((r) => r.statusCode)).toEqual([401, 401, 401, 429]);
    expect(responses.slice(0, 3).map((r) => r.json().attempts_remaining)).toEqual([2, 1, 0]);
    expect(responses[0]!.json().message).toBe(
      'Invalid email or auth hash. 2 attempts left before this account is temporarily locked.',
    );
    expect(responses[2]!.json().message).toMatch(/now temporarily locked/);

    const locked = responses[3]!;
    expect(locked.json()).toMatchObject({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'Too many failed login attempts for this account. Try again in 10 minutes.',
    });
    const retryAfter = Number(locked.headers['retry-after']);
    expect(retryAfter).toBeGreaterThan(590);
    expect(retryAfter).toBeLessThanOrEqual(600);
    expect(locked.json().retry_after_seconds).toBe(retryAfter);
  });

  it('refuses even the correct auth hash while locked, without checking it', async () => {
    const user = await newUser();
    for (let i = 0; i < 3; i++) await attempt(user.email, WRONG_HASH);
    const response = await attempt(user.email, b64(user.authHash));
    expect(response.statusCode).toBe(429);
  });

  it('does not extend the lockout with further attempts', async () => {
    const user = await newUser();
    for (let i = 0; i < 3; i++) await attempt(user.email, WRONG_HASH);
    const first = Number((await attempt(user.email, WRONG_HASH)).headers['retry-after']);
    for (let i = 0; i < 5; i++) await attempt(user.email, WRONG_HASH);
    const later = Number((await attempt(user.email, WRONG_HASH)).headers['retry-after']);
    expect(later).toBeLessThanOrEqual(first);
  });

  it('allows login again once the window has passed', async () => {
    const user = await newUser();
    for (let i = 0; i < 4; i++) await attempt(user.email, WRONG_HASH);
    await ctx.pool.query(
      `UPDATE login_failures SET window_started_at = now() - interval '11 minutes' WHERE email = $1`,
      [user.email],
    );
    expect((await attempt(user.email, b64(user.authHash))).statusCode).toBe(200);
  });

  it('resets the count after a successful login', async () => {
    const user = await newUser();
    await attempt(user.email, WRONG_HASH);
    await attempt(user.email, WRONG_HASH);
    expect((await attempt(user.email, b64(user.authHash))).statusCode).toBe(200);
    const { rowCount } = await ctx.pool.query('SELECT 1 FROM login_failures WHERE email = $1', [
      user.email,
    ]);
    expect(rowCount).toBe(0);
    expect((await attempt(user.email, WRONG_HASH)).json().attempts_remaining).toBe(2);
  });

  it('is per account: locking one account does not affect another', async () => {
    const victim = await newUser();
    const bystander = await newUser();
    for (let i = 0; i < 4; i++) await attempt(victim.email, WRONG_HASH);
    expect((await attempt(bystander.email, b64(bystander.authHash))).statusCode).toBe(200);
  });

  it('normalizes the email, so case changes do not bypass it', async () => {
    const user = await newUser();
    for (let i = 0; i < 3; i++) await attempt(user.email.toUpperCase(), WRONG_HASH);
    expect((await attempt(user.email, b64(user.authHash))).statusCode).toBe(429);
  });

  it('behaves identically for unknown emails (no account enumeration)', async () => {
    const user = await newUser();
    const known = [];
    const unknown = [];
    for (let i = 0; i < 4; i++) {
      known.push(await attempt(user.email, WRONG_HASH));
      unknown.push(await attempt(`nobody-${counter}@example.com`, WRONG_HASH));
    }
    expect(unknown.map((r) => r.statusCode)).toEqual(known.map((r) => r.statusCode));
    expect(unknown.map((r) => r.json().message)).toEqual(known.map((r) => r.json().message));
  });

  it('cannot be bypassed with concurrent requests', async () => {
    const user = await newUser();
    const responses = await Promise.all(
      Array.from({ length: 20 }, () => attempt(user.email, WRONG_HASH)),
    );
    const statuses = responses.map((r) => r.statusCode);
    expect(statuses.filter((s) => s === 401)).toHaveLength(3);
    expect(statuses.filter((s) => s === 429)).toHaveLength(17);
  });

  it('does not count malformed requests', async () => {
    const user = await newUser();
    const bad = await ctx.app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: user.email, auth_hash: 'nope' },
    });
    expect(bad.statusCode).toBe(400);
    expect((await attempt(user.email, WRONG_HASH)).json().attempts_remaining).toBe(2);
  });
});
