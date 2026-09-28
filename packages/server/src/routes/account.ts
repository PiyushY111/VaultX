import type { FastifyInstance, onRequestHookHandler } from 'fastify';
import type pg from 'pg';
import type { Config } from '../config.js';
import { isUniqueViolation, withTransaction } from '../db.js';
import { decodeBytes } from '../encoding.js';
import { conflict, forbidden, notFound } from '../http-errors.js';
import {
  AUTH_HASH_BYTES,
  CHANGE_PASSWORD_BODY_LIMIT_BYTES,
  ENCRYPTED_VAULT_KEY_BYTES,
  KDF_SALT_BYTES,
  NONCE_BYTES,
  type KdfParams,
} from '../limits.js';
import { advanceManifest, type ManifestBody } from '../manifest.js';
import {
  accountResponseSchema,
  changePasswordBodySchema,
  enableTotpBodySchema,
  itemListResponseSchema,
  reauthBodySchema,
  recoveryCodesResponseSchema,
  sessionIdParamsSchema,
  sessionListResponseSchema,
  totpSetupResponseSchema,
} from '../schemas.js';
import { hashAuthHash } from '../tokens.js';
import {
  base32Encode,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  otpauthUri,
  verifyTotp,
} from '../totp.js';
import { verifyCurrentUser, type SecondFactor } from '../verify-user.js';
import {
  ITEM_COLUMNS,
  NONCE_REUSE_MESSAGE,
  decodeCiphertext,
  toItemResponse,
  type ItemRow,
} from './vault.js';

interface ChangePasswordBody {
  current_auth_hash: string;
  auth_hash: string;
  kdf_salt: string;
  kdf_params: KdfParams;
  encrypted_vault_key: string;
  vault_key_nonce: string;
  items: { id: string; revision: number; encrypted_data: string; nonce: string }[];
  manifest: ManifestBody;
}

interface ReauthBody extends SecondFactor {
  current_auth_hash: string;
}

interface SessionRow {
  id: string;
  client: string | null;
  user_agent: string | null;
  created_at: Date;
  last_used_at: Date;
  expires_at: Date;
}

const VAULT_CHANGED_MESSAGE =
  'Your vault changed while it was being re-encrypted. Reload the vault and try again.';

const decodeAuthHash = (value: string) =>
  decodeBytes(value, 'current_auth_hash', { exact: AUTH_HASH_BYTES });

async function replaceRecoveryCodes(db: pg.PoolClient, userId: string): Promise<string[]> {
  const codes = generateRecoveryCodes();
  await db.query('DELETE FROM totp_recovery_codes WHERE user_id = $1', [userId]);
  await db.query(
    'INSERT INTO totp_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::bytea[])',
    [userId, codes.map(hashRecoveryCode)],
  );
  return codes;
}

/**
 * Sessions, master-password change, two-factor setup and account deletion.
 * Every route requires a session; the ones that change how you log in, or
 * delete data, also re-check the master password (and two-factor code).
 */
export function registerAccountRoutes(
  app: FastifyInstance,
  pool: pg.Pool,
  config: Config,
  authenticate: onRequestHookHandler,
): void {
  // Ends the session making the request. Clients call it on log out and lock.
  app.post('/logout', { onRequest: authenticate }, async (request, reply) => {
    await pool.query('DELETE FROM sessions WHERE id = $1', [request.sessionId]);
    return reply.code(204).send();
  });

  app.get(
    '/sessions',
    { onRequest: authenticate, schema: { response: { 200: sessionListResponseSchema } } },
    async (request) => {
      const { rows } = await pool.query<SessionRow>(
        `SELECT id, client, user_agent, created_at, last_used_at, expires_at FROM sessions
         WHERE user_id = $1 AND expires_at > now()
         ORDER BY last_used_at DESC, id`,
        [request.userId],
      );
      return {
        sessions: rows.map((row) => ({ ...row, current: row.id === request.sessionId })),
      };
    },
  );

  // "Sign out everywhere": ends every session of this account, including this one.
  app.delete('/sessions', { onRequest: authenticate }, async (request, reply) => {
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [request.userId]);
    return reply.code(204).send();
  });

  app.delete<{ Params: { id: string } }>(
    '/sessions/:id',
    { onRequest: authenticate, schema: { params: sessionIdParamsSchema } },
    async (request, reply) => {
      const { rowCount } = await pool.query('DELETE FROM sessions WHERE id = $1 AND user_id = $2', [
        request.params.id,
        request.userId,
      ]);
      if (!rowCount) throw notFound();
      return reply.code(204).send();
    },
  );

  /**
   * Changes the master password and rotates the vault key in one transaction.
   *
   * The client proves the current password (its auth hash), then sends new
   * KDF salt/params and auth hash, a new vault key wrapped under the new
   * password, and every item re-encrypted under that key at its next
   * revision. The server checks the item set is exactly the vault's current
   * contents, so nothing is left encrypted under the old key. Every other
   * session is ended: they hold the old vault key.
   */
  app.post<{ Body: ChangePasswordBody }>(
    '/account/password',
    {
      onRequest: authenticate,
      bodyLimit: CHANGE_PASSWORD_BODY_LIMIT_BYTES,
      config: { rateLimit: { max: config.authRateLimitMax, timeWindow: '1 minute' } },
      schema: { body: changePasswordBodySchema, response: { 200: itemListResponseSchema } },
    },
    async (request) => {
      const body = request.body;
      const currentAuthHash = decodeBytes(body.current_auth_hash, 'current_auth_hash', {
        exact: AUTH_HASH_BYTES,
      });
      const newAuthHash = decodeBytes(body.auth_hash, 'auth_hash', { exact: AUTH_HASH_BYTES });
      const kdfSalt = decodeBytes(body.kdf_salt, 'kdf_salt', { exact: KDF_SALT_BYTES });
      const encryptedVaultKey = decodeBytes(body.encrypted_vault_key, 'encrypted_vault_key', {
        exact: ENCRYPTED_VAULT_KEY_BYTES,
      });
      const vaultKeyNonce = decodeBytes(body.vault_key_nonce, 'vault_key_nonce', {
        exact: NONCE_BYTES,
      });
      const items = body.items.map((item) => ({ ...item, ...decodeCiphertext(item) }));
      const { memoryCost, iterations, parallelism } = body.kdf_params;

      // Wrong current passwords count toward the login lockout. Two-factor
      // isn't asked again: this session already passed it.
      await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { current_auth_hash: currentAuthHash },
        { requireSecondFactor: false },
      );

      let updated: ItemRow[];
      try {
        updated = await withTransaction(pool, async (db) => {
          const { rows: existing } = await db.query<{ id: string; revision: number }>(
            'SELECT id, revision FROM vault_items WHERE user_id = $1 FOR UPDATE',
            [request.userId],
          );
          const currentRevisions = new Map(existing.map((row) => [row.id, row.revision]));
          const complete =
            items.length === currentRevisions.size &&
            new Set(items.map((item) => item.id)).size === items.length &&
            items.every((item) => currentRevisions.get(item.id) === item.revision - 1);
          if (!complete) throw conflict(VAULT_CHANGED_MESSAGE);

          const { rows } = await db.query<ItemRow>(
            `UPDATE vault_items AS v
             SET encrypted_data = n.encrypted_data, nonce = n.nonce, revision = n.revision,
                 updated_at = now()
             FROM unnest($2::uuid[], $3::integer[], $4::bytea[], $5::bytea[])
               AS n (id, revision, encrypted_data, nonce)
             WHERE v.id = n.id AND v.user_id = $1
             RETURNING ${ITEM_COLUMNS.split(', ')
               .map((column) => `v.${column}`)
               .join(', ')}`,
            [
              request.userId,
              items.map((item) => item.id),
              items.map((item) => item.revision),
              items.map((item) => item.encryptedData),
              items.map((item) => item.nonce),
            ],
          );
          // The manifest, re-encrypted under the new vault key, moves on with the items.
          await advanceManifest(db, request.userId, body.manifest);
          await db.query(
            `UPDATE users SET auth_hash = $2, kdf_salt = $3, kdf_params = $4,
               encrypted_vault_key = $5, vault_key_nonce = $6
             WHERE id = $1`,
            [
              request.userId,
              hashAuthHash(newAuthHash),
              kdfSalt,
              { memoryCost, iterations, parallelism },
              encryptedVaultKey,
              vaultKeyNonce,
            ],
          );
          await db.query('DELETE FROM sessions WHERE user_id = $1 AND id <> $2', [
            request.userId,
            request.sessionId,
          ]);
          return rows;
        });
      } catch (error) {
        if (isUniqueViolation(error)) throw conflict(NONCE_REUSE_MESSAGE);
        throw error;
      }

      const order = new Map(items.map((item, index) => [item.id, index]));
      updated.sort((a, b) => order.get(a.id)! - order.get(b.id)!);
      return { items: updated.map(toItemResponse) };
    },
  );

  const sensitive = {
    onRequest: authenticate,
    config: { rateLimit: { max: config.authRateLimitMax, timeWindow: '1 minute' } },
  };

  app.get(
    '/account',
    { onRequest: authenticate, schema: { response: { 200: accountResponseSchema } } },
    async (request) => {
      const { rows } = await pool.query<{
        email: string;
        created_at: Date;
        totp_enabled: boolean;
        recovery_codes_remaining: number;
      }>(
        `SELECT email, created_at, totp_secret IS NOT NULL AS totp_enabled,
           (SELECT count(*)::int FROM totp_recovery_codes WHERE user_id = users.id)
             AS recovery_codes_remaining
         FROM users WHERE id = $1`,
        [request.userId],
      );
      return rows[0]!;
    },
  );

  // Step 1 of turning on two-factor: a new secret for the user's
  // authenticator app. Nothing changes until it's confirmed with a code.
  app.post(
    '/account/totp/setup',
    { ...sensitive, schema: { response: { 200: totpSetupResponseSchema } } },
    async (request) => {
      const secret = generateTotpSecret();
      const { rows } = await pool.query<{ email: string }>(
        `UPDATE users SET totp_pending_secret = $2
         WHERE id = $1 AND totp_secret IS NULL
         RETURNING email`,
        [request.userId, secret],
      );
      if (!rows[0]) throw conflict('Two-factor authentication is already on.');
      return { secret: base32Encode(secret), otpauth_uri: otpauthUri(rows[0].email, secret) };
    },
  );

  // Step 2: the master password plus a code from the app proves it was set
  // up correctly. Returns one-time recovery codes, shown only this once.
  app.post<{ Body: { current_auth_hash: string; totp_code: string } }>(
    '/account/totp/enable',
    {
      ...sensitive,
      schema: { body: enableTotpBodySchema, response: { 200: recoveryCodesResponseSchema } },
    },
    async (request) => {
      await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { current_auth_hash: decodeAuthHash(request.body.current_auth_hash) },
        { requireSecondFactor: false },
      );
      const recoveryCodes = await withTransaction(pool, async (db) => {
        const { rows } = await db.query<{ totp_pending_secret: Buffer | null; enabled: boolean }>(
          `SELECT totp_pending_secret, totp_secret IS NOT NULL AS enabled
           FROM users WHERE id = $1 FOR UPDATE`,
          [request.userId],
        );
        const { totp_pending_secret: pending, enabled } = rows[0]!;
        if (enabled) throw conflict('Two-factor authentication is already on.');
        if (!pending) throw conflict('Start two-factor setup first.');
        const step = verifyTotp(pending, request.body.totp_code, 0);
        if (step === null) {
          throw forbidden('That code doesn’t match. Check the time on your device and try again.');
        }
        await db.query(
          `UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL,
             totp_last_step = $2
           WHERE id = $1`,
          [request.userId, step],
        );
        return replaceRecoveryCodes(db, request.userId);
      });
      return { recovery_codes: recoveryCodes };
    },
  );

  app.post<{ Body: ReauthBody }>(
    '/account/totp/disable',
    { ...sensitive, schema: { body: reauthBodySchema } },
    async (request, reply) => {
      await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { ...request.body, current_auth_hash: decodeAuthHash(request.body.current_auth_hash) },
        { requireSecondFactor: true },
      );
      await withTransaction(pool, async (db) => {
        await db.query(
          `UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL, totp_last_step = 0
           WHERE id = $1`,
          [request.userId],
        );
        await db.query('DELETE FROM totp_recovery_codes WHERE user_id = $1', [request.userId]);
      });
      return reply.code(204).send();
    },
  );

  app.post<{ Body: ReauthBody }>(
    '/account/totp/recovery-codes',
    {
      ...sensitive,
      schema: { body: reauthBodySchema, response: { 200: recoveryCodesResponseSchema } },
    },
    async (request) => {
      await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { ...request.body, current_auth_hash: decodeAuthHash(request.body.current_auth_hash) },
        { requireSecondFactor: true },
      );
      const { rows } = await pool.query<{ enabled: boolean }>(
        'SELECT totp_secret IS NOT NULL AS enabled FROM users WHERE id = $1',
        [request.userId],
      );
      if (!rows[0]?.enabled) throw conflict('Two-factor authentication is off.');
      return {
        recovery_codes: await withTransaction(pool, (db) =>
          replaceRecoveryCodes(db, request.userId),
        ),
      };
    },
  );

  // Deletes the account and everything in it: items, sessions, codes.
  app.delete<{ Body: ReauthBody }>(
    '/account',
    { ...sensitive, schema: { body: reauthBodySchema } },
    async (request, reply) => {
      const { email } = await verifyCurrentUser(
        pool,
        config,
        request.userId,
        { ...request.body, current_auth_hash: decodeAuthHash(request.body.current_auth_hash) },
        { requireSecondFactor: true },
      );
      await withTransaction(pool, async (db) => {
        await db.query('DELETE FROM users WHERE id = $1', [request.userId]);
        await db.query('DELETE FROM login_failures WHERE email = $1', [email]);
      });
      return reply.code(204).send();
    },
  );
}
