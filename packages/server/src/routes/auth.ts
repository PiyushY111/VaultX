import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import type { Config } from '../config.js';
import { isUniqueViolation } from '../db.js';
import { decodeBytes, encodeBytes } from '../encoding.js';
import { conflict, tooManyRequests, unauthorized } from '../http-errors.js';
import {
  AUTH_HASH_BYTES,
  DEFAULT_KDF_PARAMS,
  ENCRYPTED_VAULT_KEY_BYTES,
  KDF_SALT_BYTES,
  NONCE_BYTES,
  type KdfParams,
} from '../limits.js';
import { clearLoginFailures, refundLoginAttempt, reserveLoginAttempt } from '../login-throttle.js';
import {
  loginBodySchema,
  loginResponseSchema,
  preloginBodySchema,
  preloginResponseSchema,
  signupBodySchema,
  signupResponseSchema,
} from '../schemas.js';
import {
  DUMMY_AUTH_HASH,
  authHashMatches,
  fakeKdfSalt,
  generateSessionToken,
  hashAuthHash,
} from '../tokens.js';
import { SECOND_FACTOR_REQUIRED, consumeSecondFactor, type SecondFactor } from '../verify-user.js';

interface SignupBody {
  email: string;
  auth_hash: string;
  encrypted_vault_key: string;
  vault_key_nonce: string;
  kdf_salt: string;
  kdf_params: KdfParams;
}

interface LoginBody extends SecondFactor {
  email: string;
  auth_hash: string;
  client?: 'web' | 'extension';
}

const MAX_USER_AGENT_LENGTH = 256;

const normalizeEmail = (email: string): string => email.toLowerCase();

export function registerAuthRoutes(app: FastifyInstance, pool: pg.Pool, config: Config): void {
  const rateLimit = { max: config.authRateLimitMax, timeWindow: '1 minute' };

  // All cryptography happens client-side; the server validates shapes and stores the result.
  app.post<{ Body: SignupBody }>(
    '/signup',
    {
      config: { rateLimit },
      schema: { body: signupBodySchema, response: { 201: signupResponseSchema } },
    },
    async (request, reply) => {
      const body = request.body;
      const { memoryCost, iterations, parallelism } = body.kdf_params;
      try {
        const { rows } = await pool.query<{ id: string }>(
          `INSERT INTO users (email, kdf_salt, kdf_params, auth_hash, encrypted_vault_key, vault_key_nonce)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id`,
          [
            normalizeEmail(body.email),
            decodeBytes(body.kdf_salt, 'kdf_salt', { exact: KDF_SALT_BYTES }),
            { memoryCost, iterations, parallelism },
            hashAuthHash(decodeBytes(body.auth_hash, 'auth_hash', { exact: AUTH_HASH_BYTES })),
            decodeBytes(body.encrypted_vault_key, 'encrypted_vault_key', {
              exact: ENCRYPTED_VAULT_KEY_BYTES,
            }),
            decodeBytes(body.vault_key_nonce, 'vault_key_nonce', { exact: NONCE_BYTES }),
          ],
        );
        reply.code(201);
        return { id: rows[0]!.id };
      } catch (error) {
        if (isUniqueViolation(error)) throw conflict('An account with this email already exists');
        throw error;
      }
    },
  );

  // Returns the KDF salt and params the client needs to derive its authHash
  // before it can log in. Unknown emails get a stable fake salt and default
  // params, so this endpoint doesn't reveal which emails have accounts.
  app.post<{ Body: { email: string } }>(
    '/prelogin',
    {
      config: { rateLimit },
      schema: { body: preloginBodySchema, response: { 200: preloginResponseSchema } },
    },
    async (request) => {
      const email = normalizeEmail(request.body.email);
      const { rows } = await pool.query<{ kdf_salt: Buffer; kdf_params: KdfParams }>(
        'SELECT kdf_salt, kdf_params FROM users WHERE email = $1',
        [email],
      );
      const user = rows[0];
      if (user) return { kdf_salt: encodeBytes(user.kdf_salt), kdf_params: user.kdf_params };
      return {
        kdf_salt: encodeBytes(fakeKdfSalt(config.preloginSecret, email)),
        kdf_params: DEFAULT_KDF_PARAMS,
      };
    },
  );

  app.post<{ Body: LoginBody }>(
    '/login',
    {
      config: { rateLimit },
      schema: { body: loginBodySchema, response: { 200: loginResponseSchema } },
    },
    async (request, reply) => {
      const authHash = decodeBytes(request.body.auth_hash, 'auth_hash', { exact: AUTH_HASH_BYTES });
      const email = normalizeEmail(request.body.email);

      // Per-account limit on failed attempts (applies to unknown emails too,
      // so it reveals nothing about which accounts exist).
      const attempt = await reserveLoginAttempt(pool, email, config.loginThrottle);
      if (!attempt.allowed) {
        const minutes = Math.ceil(attempt.retryAfterSeconds / 60);
        reply.header('retry-after', String(attempt.retryAfterSeconds));
        throw tooManyRequests(
          `Too many failed login attempts for this account. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
          { retry_after_seconds: attempt.retryAfterSeconds },
        );
      }

      const { rows } = await pool.query<{ id: string; auth_hash: Buffer; totp_enabled: boolean }>(
        'SELECT id, auth_hash, totp_secret IS NOT NULL AS totp_enabled FROM users WHERE email = $1',
        [email],
      );
      const user = rows[0];
      // Always do the comparison, even for unknown emails, and give the same
      // error either way.
      const matches = authHashMatches(authHash, user?.auth_hash ?? DUMMY_AUTH_HASH);
      if (!user || !matches) {
        const remaining = attempt.attemptsRemaining;
        throw unauthorized(
          remaining > 0
            ? `Invalid email or auth hash. ${remaining} attempt${remaining === 1 ? '' : 's'} left before this account is temporarily locked.`
            : 'Invalid email or auth hash. This account is now temporarily locked after too many failed attempts.',
          { attempts_remaining: remaining },
        );
      }

      // Only now, with the password proven, is two-factor mentioned at all,
      // so it reveals nothing about accounts to someone without the password.
      if (user.totp_enabled) {
        if (!request.body.totp_code && !request.body.recovery_code) {
          // Asking for the code isn't a failed attempt.
          await refundLoginAttempt(pool, email);
          throw unauthorized(SECOND_FACTOR_REQUIRED, { totp_required: true });
        }
        if (!(await consumeSecondFactor(pool, user.id, request.body))) {
          const remaining = attempt.attemptsRemaining;
          throw unauthorized(
            `That two-factor code is incorrect or was already used. ${remaining} attempt${remaining === 1 ? '' : 's'} left before this account is temporarily locked.`,
            { totp_required: true, attempts_remaining: remaining },
          );
        }
      }
      await clearLoginFailures(pool, email);

      const { token, tokenHash } = generateSessionToken();
      const expiresAt = new Date(Date.now() + config.sessionTtlSeconds * 1000);
      await pool.query('DELETE FROM sessions WHERE user_id = $1 AND expires_at <= now()', [
        user.id,
      ]);
      await pool.query(
        `INSERT INTO sessions (user_id, token_hash, expires_at, client, user_agent)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          user.id,
          tokenHash,
          expiresAt,
          request.body.client ?? null,
          request.headers['user-agent']?.slice(0, MAX_USER_AGENT_LENGTH) ?? null,
        ],
      );
      return { token, expires_at: expiresAt };
    },
  );
}
