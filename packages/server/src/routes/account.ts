import type { FastifyInstance, onRequestHookHandler } from 'fastify';
import type pg from 'pg';
import type { Config } from '../config.js';
import { isUniqueViolation } from '../db.js';
import { decodeBytes } from '../encoding.js';
import { conflict, forbidden, notFound, tooManyRequests } from '../http-errors.js';
import {
  AUTH_HASH_BYTES,
  CHANGE_PASSWORD_BODY_LIMIT_BYTES,
  ENCRYPTED_VAULT_KEY_BYTES,
  KDF_SALT_BYTES,
  NONCE_BYTES,
  type KdfParams,
} from '../limits.js';
import { clearLoginFailures, reserveLoginAttempt } from '../login-throttle.js';
import {
  changePasswordBodySchema,
  itemListResponseSchema,
  sessionIdParamsSchema,
  sessionListResponseSchema,
} from '../schemas.js';
import { authHashMatches, hashAuthHash } from '../tokens.js';
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

/** Session management and master-password change. Every route requires a session. */
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

      const { rows: users } = await pool.query<{ email: string }>(
        'SELECT email FROM users WHERE id = $1',
        [request.userId],
      );
      const email = users[0]?.email;
      if (!email) throw notFound();

      // A stolen session token must not become an unthrottled password oracle,
      // so wrong current passwords count against the same per-account budget
      // as failed logins.
      const attempt = await reserveLoginAttempt(pool, email, config.loginThrottle);
      if (!attempt.allowed) {
        throw tooManyRequests('Too many incorrect attempts. Try again later.', {
          retry_after_seconds: attempt.retryAfterSeconds,
        });
      }

      const client = await pool.connect();
      let updated: ItemRow[];
      let passwordVerified = false;
      try {
        await client.query('BEGIN');
        const { rows } = await client.query<{ auth_hash: Buffer }>(
          'SELECT auth_hash FROM users WHERE id = $1 FOR UPDATE',
          [request.userId],
        );
        if (!authHashMatches(currentAuthHash, rows[0]!.auth_hash)) {
          throw forbidden('Current master password is incorrect.', {
            attempts_remaining: attempt.attemptsRemaining,
          });
        }
        passwordVerified = true;

        const { rows: existing } = await client.query<{ id: string; revision: number }>(
          'SELECT id, revision FROM vault_items WHERE user_id = $1 FOR UPDATE',
          [request.userId],
        );
        const currentRevisions = new Map(existing.map((row) => [row.id, row.revision]));
        const complete =
          items.length === currentRevisions.size &&
          new Set(items.map((item) => item.id)).size === items.length &&
          items.every((item) => currentRevisions.get(item.id) === item.revision - 1);
        if (!complete) throw conflict(VAULT_CHANGED_MESSAGE);

        ({ rows: updated } = await client.query<ItemRow>(
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
        ));
        await client.query(
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
        await client.query('DELETE FROM sessions WHERE user_id = $1 AND id <> $2', [
          request.userId,
          request.sessionId,
        ]);
        await client.query('COMMIT');
      } catch (error) {
        // Also undoes the transaction for the 403 and 409 thrown above.
        await client.query('ROLLBACK').catch(() => {});
        if (isUniqueViolation(error)) throw conflict(NONCE_REUSE_MESSAGE);
        throw error;
      } finally {
        client.release();
        // The right password shouldn't use up an attempt, even if the change
        // itself is refused (e.g. the vault changed meanwhile).
        if (passwordVerified) await clearLoginFailures(pool, email);
      }

      const order = new Map(items.map((item, index) => [item.id, index]));
      updated.sort((a, b) => order.get(a.id)! - order.get(b.id)!);
      return { items: updated.map(toItemResponse) };
    },
  );
}
