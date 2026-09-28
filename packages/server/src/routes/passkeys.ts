import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import type { FastifyInstance, onRequestHookHandler } from 'fastify';
import type pg from 'pg';
import type { Config } from '../config.js';
import { isUniqueViolation, withTransaction } from '../db.js';
import { decodeBytes } from '../encoding.js';
import { badRequest, conflict, notFound } from '../http-errors.js';
import { AUTH_HASH_BYTES } from '../limits.js';
import { replaceRecoveryCodes } from '../recovery-codes.js';
import {
  passkeyListResponseSchema,
  passkeyRegisterFinishBodySchema,
  passkeyRegisteredResponseSchema,
  passkeyRenameBodySchema,
  passkeyRequiredBodySchema,
  reauthBodySchema,
  sessionIdParamsSchema,
  webauthnOptionsResponseSchema,
} from '../schemas.js';
import {
  loadSecondFactorState,
  secondFactorEnabled,
  verifyCurrentUser,
  type SecondFactor,
} from '../verify-user.js';
import {
  MAX_PASSKEYS_PER_USER,
  authenticationOptions,
  registrationOptions,
  verifyRegistration,
} from '../webauthn.js';

interface ReauthBody extends SecondFactor {
  current_auth_hash: string;
}

interface PasskeyRow {
  id: string;
  name: string;
  transports: string[];
  created_at: Date;
  last_used_at: Date | null;
}

const PASSKEY_COLUMNS = 'id, name, transports, created_at, last_used_at';

const decodeAuthHash = (value: string) =>
  decodeBytes(value, 'current_auth_hash', { exact: AUTH_HASH_BYTES });

const LAST_REQUIRED_PASSKEY =
  'This is your only passkey and the account requires one. Turn off “Require passkey” first, or add another passkey.';

/**
 * Passkeys (WebAuthn) as a second factor.
 *
 *   POST   /account/passkeys/register/options  begin registration (password + existing 2FA)
 *   POST   /account/passkeys                   finish registration
 *   GET    /account/passkeys                   list
 *   PATCH  /account/passkeys/:id               rename
 *   DELETE /account/passkeys/:id               delete (password + 2FA)
 *   POST   /account/passkeys/reauth-options    begin a passkey re-authentication
 *   PUT    /account/passkeys/required          "Require passkey" on/off (password + 2FA)
 *
 * Logging in with a passkey goes through POST /login: once the password is
 * proven, its "second factor needed" reply carries the WebAuthn options, and
 * the assertion comes back in the `webauthn` field.
 */
export function registerPasskeyRoutes(
  app: FastifyInstance,
  pool: pg.Pool,
  config: Config,
  authenticate: onRequestHookHandler,
): void {
  const sensitive = {
    onRequest: authenticate,
    config: { rateLimit: { max: config.authRateLimitMax, timeWindow: '1 minute' } },
  };

  // Registering a passkey adds a way to log in, so it takes the master
  // password and, if the account already has a second factor, one of those.
  // The challenge this returns is what carries that proof to the finish step:
  // it is bound to this user and to registration, and lasts two minutes.
  app.post<{ Body: ReauthBody }>(
    '/account/passkeys/register/options',
    {
      ...sensitive,
      schema: { body: reauthBodySchema, response: { 200: webauthnOptionsResponseSchema } },
    },
    async (request) => {
      const { email, secondFactor } = await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { ...request.body, current_auth_hash: decodeAuthHash(request.body.current_auth_hash) },
        { requireSecondFactor: true },
      );
      if (secondFactor.passkeys >= MAX_PASSKEYS_PER_USER) {
        throw conflict(`An account can have at most ${MAX_PASSKEYS_PER_USER} passkeys.`);
      }
      return {
        options: await registrationOptions(pool, config.webauthn, { id: request.userId, email }),
      };
    },
  );

  app.post<{ Body: { name: string; response: RegistrationResponseJSON } }>(
    '/account/passkeys',
    {
      ...sensitive,
      schema: {
        body: passkeyRegisterFinishBodySchema,
        response: { 201: passkeyRegisteredResponseSchema },
      },
    },
    async (request, reply) => {
      const name = request.body.name.trim();
      const result = await withTransaction(pool, async (db) => {
        // Serializes registrations (and factor changes) for this account.
        await db.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [request.userId]);
        const before = await loadSecondFactorState(db, request.userId);
        if (before.passkeys >= MAX_PASSKEYS_PER_USER) {
          throw conflict(`An account can have at most ${MAX_PASSKEYS_PER_USER} passkeys.`);
        }
        const verified = await verifyRegistration(
          db,
          config.webauthn,
          request.userId,
          request.body.response,
        );
        if (!verified) return null;
        let passkey: PasskeyRow;
        try {
          const { rows } = await db.query<PasskeyRow>(
            `INSERT INTO webauthn_credentials
               (user_id, credential_id, public_key, sign_counter, transports, name)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING ${PASSKEY_COLUMNS}`,
            [
              request.userId,
              verified.credentialId,
              verified.publicKey,
              verified.counter,
              verified.transports,
              name,
            ],
          );
          passkey = rows[0]!;
        } catch (error) {
          if (isUniqueViolation(error)) throw conflict('This passkey is already registered.');
          throw error;
        }
        // The account's first second factor comes with recovery codes, so a
        // lost passkey doesn't mean a lost account.
        const recoveryCodes = secondFactorEnabled(before)
          ? undefined
          : await replaceRecoveryCodes(db, request.userId);
        return { passkey, recoveryCodes };
      });
      // Outside the transaction, so the used challenge stays used.
      if (!result) {
        throw badRequest(
          'That passkey couldn’t be verified. It may have taken too long, or been made for a different site. Try again.',
        );
      }
      return reply.code(201).send({
        passkey: result.passkey,
        ...(result.recoveryCodes && { recovery_codes: result.recoveryCodes }),
      });
    },
  );

  app.get(
    '/account/passkeys',
    { onRequest: authenticate, schema: { response: { 200: passkeyListResponseSchema } } },
    async (request) => {
      const { rows } = await pool.query<PasskeyRow>(
        `SELECT ${PASSKEY_COLUMNS} FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`,
        [request.userId],
      );
      return { passkeys: rows };
    },
  );

  // Renaming changes only a label the user sees, so the session is enough.
  app.patch<{ Params: { id: string }; Body: { name: string } }>(
    '/account/passkeys/:id',
    {
      onRequest: authenticate,
      schema: { params: sessionIdParamsSchema, body: passkeyRenameBodySchema },
    },
    async (request) => {
      const { rows } = await pool.query<PasskeyRow>(
        `UPDATE webauthn_credentials SET name = $3 WHERE id = $1 AND user_id = $2
         RETURNING ${PASSKEY_COLUMNS}`,
        [request.params.id, request.userId, request.body.name.trim()],
      );
      if (!rows[0]) throw notFound('Passkey not found');
      return { passkey: rows[0] };
    },
  );

  // Deleting always takes the password and a second factor. When it's the
  // account's last second factor, two-factor login is off afterwards, and the
  // recovery codes go with it.
  app.delete<{ Params: { id: string }; Body: ReauthBody }>(
    '/account/passkeys/:id',
    { ...sensitive, schema: { params: sessionIdParamsSchema, body: reauthBodySchema } },
    async (request, reply) => {
      const { rowCount } = await pool.query(
        'SELECT 1 FROM webauthn_credentials WHERE id = $1 AND user_id = $2',
        [request.params.id, request.userId],
      );
      if (!rowCount) throw notFound('Passkey not found');
      // Checked before the second factor is spent.
      const state = await loadSecondFactorState(pool, request.userId);
      if (state.passkeyRequired && state.passkeys <= 1) throw conflict(LAST_REQUIRED_PASSKEY);

      await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { ...request.body, current_auth_hash: decodeAuthHash(request.body.current_auth_hash) },
        { requireSecondFactor: true },
      );
      await withTransaction(pool, async (db) => {
        await db.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [request.userId]);
        const { rowCount: deleted } = await db.query(
          'DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2',
          [request.params.id, request.userId],
        );
        if (!deleted) throw notFound('Passkey not found');
        const after = await loadSecondFactorState(db, request.userId);
        // Re-checked under the lock, in case "Require passkey" changed meanwhile.
        if (after.passkeyRequired && after.passkeys === 0) throw conflict(LAST_REQUIRED_PASSKEY);
        if (!secondFactorEnabled(after)) {
          await db.query('DELETE FROM totp_recovery_codes WHERE user_id = $1', [request.userId]);
        }
      });
      return reply.code(204).send();
    },
  );

  // For account changes that need a second factor: a challenge the client
  // signs with a passkey and sends back as `webauthn`.
  app.post(
    '/account/passkeys/reauth-options',
    { ...sensitive, schema: { response: { 200: webauthnOptionsResponseSchema } } },
    async (request) => {
      const state = await loadSecondFactorState(pool, request.userId);
      if (state.passkeys === 0) throw conflict('This account has no passkeys.');
      return {
        options: await authenticationOptions(pool, config.webauthn, request.userId, 'reauth'),
      };
    },
  );

  // "Require passkey": TOTP codes stop counting as a second factor, for
  // logging in and for account changes. Recovery codes still work.
  app.put<{ Body: ReauthBody & { required: boolean } }>(
    '/account/passkeys/required',
    { ...sensitive, schema: { body: passkeyRequiredBodySchema } },
    async (request, reply) => {
      const { required, ...reauth } = request.body;
      if (required && (await loadSecondFactorState(pool, request.userId)).passkeys === 0) {
        throw conflict('Add a passkey first.');
      }
      await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { ...reauth, current_auth_hash: decodeAuthHash(reauth.current_auth_hash) },
        { requireSecondFactor: true },
      );
      const { rowCount } = await pool.query(
        `UPDATE users SET webauthn_required = $2
         WHERE id = $1
           AND (NOT $2 OR EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = $1))`,
        [request.userId, required],
      );
      if (!rowCount) throw conflict('Add a passkey first.');
      return reply.code(204).send();
    },
  );
}
