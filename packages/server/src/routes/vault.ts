import type { FastifyInstance, onRequestHookHandler } from 'fastify';
import type pg from 'pg';
import { isUniqueViolation, withTransaction } from '../db.js';
import { decodeBytes, encodeBytes } from '../encoding.js';
import { conflict, notFound } from '../http-errors.js';
import { MAX_ITEM_CIPHERTEXT_BYTES, NONCE_BYTES, TAG_BYTES, type KdfParams } from '../limits.js';
import {
  advanceManifest,
  isCurrentManifest,
  toManifestResponse,
  type ManifestBody,
} from '../manifest.js';
import {
  createItemBodySchema,
  deleteItemBodySchema,
  itemIdParamsSchema,
  itemResponseSchema,
  manifestBodySchema,
  updateItemBodySchema,
  vaultKeyResponseSchema,
  vaultResponseSchema,
} from '../schemas.js';

interface CiphertextBody {
  encrypted_data: string;
  nonce: string;
}

interface CreateItemBody extends CiphertextBody {
  id: string;
  revision: number;
  manifest: ManifestBody;
}

interface UpdateItemBody extends CiphertextBody {
  revision: number;
  manifest: ManifestBody;
}

export interface ItemRow {
  id: string;
  revision: number;
  encrypted_data: Buffer;
  nonce: Buffer;
  created_at: Date;
  updated_at: Date;
}

export const ITEM_COLUMNS = 'id, revision, encrypted_data, nonce, created_at, updated_at';

export const toItemResponse = (row: ItemRow) => ({
  id: row.id,
  revision: row.revision,
  encrypted_data: encodeBytes(row.encrypted_data),
  nonce: encodeBytes(row.nonce),
  created_at: row.created_at,
  updated_at: row.updated_at,
});

export function decodeCiphertext(body: CiphertextBody): { encryptedData: Buffer; nonce: Buffer } {
  return {
    encryptedData: decodeBytes(body.encrypted_data, 'encrypted_data', {
      min: TAG_BYTES,
      max: MAX_ITEM_CIPHERTEXT_BYTES,
    }),
    nonce: decodeBytes(body.nonce, 'nonce', { exact: NONCE_BYTES }),
  };
}

export const NONCE_REUSE_MESSAGE = 'nonce has already been used; encrypt with a fresh random nonce';
const NONCE_CONSTRAINT = 'vault_items_nonce_key';

const staleRevision = (current: number) =>
  conflict('This item was changed elsewhere since it was loaded. Reload the vault and try again.', {
    current_revision: current,
  });

/**
 * Vault routes. The server treats every payload as opaque ciphertext: it
 * checks lengths and ownership, and stores and returns bytes unchanged.
 */
export function registerVaultRoutes(
  app: FastifyInstance,
  pool: pg.Pool,
  authenticate: onRequestHookHandler,
): void {
  app.get(
    '/vault-key',
    { onRequest: authenticate, schema: { response: { 200: vaultKeyResponseSchema } } },
    async (request) => {
      const { rows } = await pool.query<{
        encrypted_vault_key: Buffer;
        vault_key_nonce: Buffer;
        kdf_salt: Buffer;
        kdf_params: KdfParams;
      }>(
        'SELECT encrypted_vault_key, vault_key_nonce, kdf_salt, kdf_params FROM users WHERE id = $1',
        [request.userId],
      );
      const user = rows[0];
      if (!user) throw notFound();
      return {
        encrypted_vault_key: encodeBytes(user.encrypted_vault_key),
        vault_key_nonce: encodeBytes(user.vault_key_nonce),
        kdf_salt: encodeBytes(user.kdf_salt),
        kdf_params: user.kdf_params,
      };
    },
  );

  app.get(
    '/vault-items',
    { onRequest: authenticate, schema: { response: { 200: vaultResponseSchema } } },
    async (request) => {
      // One snapshot, so the manifest and items always match.
      return withTransaction(pool, async (db) => {
        await db.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        const { rows } = await db.query<ItemRow>(
          `SELECT ${ITEM_COLUMNS} FROM vault_items WHERE user_id = $1 ORDER BY created_at, id`,
          [request.userId],
        );
        const { rows: users } = await db.query<{
          manifest_version: number;
          encrypted_manifest: Buffer | null;
          manifest_nonce: Buffer | null;
        }>('SELECT manifest_version, encrypted_manifest, manifest_nonce FROM users WHERE id = $1', [
          request.userId,
        ]);
        return { items: rows.map(toItemResponse), manifest: toManifestResponse(users[0]!) };
      });
    },
  );

  // Writes a new manifest without changing any item: a vault's first
  // manifest, written by whichever client loads it first.
  app.put<{ Body: ManifestBody }>(
    '/vault-manifest',
    { onRequest: authenticate, schema: { body: manifestBodySchema } },
    async (request, reply) => {
      await withTransaction(pool, (db) => advanceManifest(db, request.userId, request.body));
      return reply.code(204).send();
    },
  );

  // The client picks the id (it's bound into the ciphertext) and starts at revision 1.
  app.post<{ Body: CreateItemBody }>(
    '/vault-items',
    {
      onRequest: authenticate,
      schema: { body: createItemBodySchema, response: { 201: itemResponseSchema } },
    },
    async (request, reply) => {
      const { encryptedData, nonce } = decodeCiphertext(request.body);
      try {
        const row = await withTransaction(pool, async (db) => {
          const { rows } = await db.query<ItemRow>(
            `INSERT INTO vault_items (id, user_id, revision, encrypted_data, nonce)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING ${ITEM_COLUMNS}`,
            [request.body.id, request.userId, request.body.revision, encryptedData, nonce],
          );
          await advanceManifest(db, request.userId, request.body.manifest);
          return rows[0]!;
        });
        reply.code(201);
        return toItemResponse(row);
      } catch (error) {
        if (isUniqueViolation(error, NONCE_CONSTRAINT)) throw conflict(NONCE_REUSE_MESSAGE);
        if (isUniqueViolation(error)) throw conflict('An item with this id already exists');
        throw error;
      }
    },
  );

  // Accepts only the next revision, so a stale client can't overwrite a newer
  // save, and a revision number is never reused for different content.
  app.put<{ Params: { id: string }; Body: UpdateItemBody }>(
    '/vault-items/:id',
    {
      onRequest: authenticate,
      schema: {
        params: itemIdParamsSchema,
        body: updateItemBodySchema,
        response: { 200: itemResponseSchema },
      },
    },
    async (request) => {
      const { encryptedData, nonce } = decodeCiphertext(request.body);
      const { revision, manifest } = request.body;
      try {
        return await withTransaction(pool, async (db) => {
          // Also rejects re-encrypting new content under the item's current nonce.
          const { rows } = await db.query<ItemRow>(
            `UPDATE vault_items
             SET encrypted_data = $3, nonce = $4, revision = $5, updated_at = now()
             WHERE id = $1 AND user_id = $2 AND revision = $5 - 1 AND nonce <> $4
             RETURNING ${ITEM_COLUMNS}`,
            [request.params.id, request.userId, encryptedData, nonce, revision],
          );
          const row = rows[0];
          if (row) {
            await advanceManifest(db, request.userId, manifest);
            return toItemResponse(row);
          }

          const { rows: current } = await db.query<ItemRow>(
            `SELECT ${ITEM_COLUMNS} FROM vault_items WHERE id = $1 AND user_id = $2`,
            [request.params.id, request.userId],
          );
          const existing = current[0];
          // Other users' items are indistinguishable from missing ones.
          if (!existing) throw notFound();
          const isRetry =
            existing.revision === revision &&
            existing.nonce.equals(nonce) &&
            existing.encrypted_data.equals(encryptedData) &&
            (await isCurrentManifest(db, request.userId, manifest));
          // Resending the identical save is a harmless retry (e.g. after a lost response).
          if (isRetry) return toItemResponse(existing);
          if (existing.nonce.equals(nonce)) throw conflict(NONCE_REUSE_MESSAGE);
          throw staleRevision(existing.revision);
        });
      } catch (error) {
        if (isUniqueViolation(error, NONCE_CONSTRAINT)) throw conflict(NONCE_REUSE_MESSAGE);
        throw error;
      }
    },
  );

  app.delete<{ Params: { id: string }; Body: { manifest: ManifestBody } }>(
    '/vault-items/:id',
    { onRequest: authenticate, schema: { params: itemIdParamsSchema, body: deleteItemBodySchema } },
    async (request, reply) => {
      await withTransaction(pool, async (db) => {
        const { rowCount } = await db.query(
          'DELETE FROM vault_items WHERE id = $1 AND user_id = $2',
          [request.params.id, request.userId],
        );
        if (!rowCount) throw notFound();
        await advanceManifest(db, request.userId, request.body.manifest);
      });
      return reply.code(204).send();
    },
  );
}
