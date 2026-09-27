import type { FastifyInstance, onRequestHookHandler } from 'fastify';
import type pg from 'pg';
import { isUniqueViolation } from '../db.js';
import { decodeBytes, encodeBytes } from '../encoding.js';
import { conflict, notFound } from '../http-errors.js';
import { MAX_ITEM_CIPHERTEXT_BYTES, NONCE_BYTES, TAG_BYTES, type KdfParams } from '../limits.js';
import {
  itemBodySchema,
  itemIdParamsSchema,
  itemListResponseSchema,
  itemResponseSchema,
  vaultKeyResponseSchema,
} from '../schemas.js';

interface ItemBody {
  encrypted_data: string;
  nonce: string;
}

interface ItemRow {
  id: string;
  encrypted_data: Buffer;
  nonce: Buffer;
  created_at: Date;
  updated_at: Date;
}

const ITEM_COLUMNS = 'id, encrypted_data, nonce, created_at, updated_at';

const toItemResponse = (row: ItemRow) => ({
  id: row.id,
  encrypted_data: encodeBytes(row.encrypted_data),
  nonce: encodeBytes(row.nonce),
  created_at: row.created_at,
  updated_at: row.updated_at,
});

function decodeItem(body: ItemBody): { encryptedData: Buffer; nonce: Buffer } {
  return {
    encryptedData: decodeBytes(body.encrypted_data, 'encrypted_data', {
      min: TAG_BYTES,
      max: MAX_ITEM_CIPHERTEXT_BYTES,
    }),
    nonce: decodeBytes(body.nonce, 'nonce', { exact: NONCE_BYTES }),
  };
}

const NONCE_REUSE_MESSAGE = 'nonce has already been used; encrypt with a fresh random nonce';

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
    { onRequest: authenticate, schema: { response: { 200: itemListResponseSchema } } },
    async (request) => {
      const { rows } = await pool.query<ItemRow>(
        `SELECT ${ITEM_COLUMNS} FROM vault_items WHERE user_id = $1 ORDER BY created_at, id`,
        [request.userId],
      );
      return { items: rows.map(toItemResponse) };
    },
  );

  app.post<{ Body: ItemBody }>(
    '/vault-items',
    {
      onRequest: authenticate,
      schema: { body: itemBodySchema, response: { 201: itemResponseSchema } },
    },
    async (request, reply) => {
      const { encryptedData, nonce } = decodeItem(request.body);
      try {
        const { rows } = await pool.query<ItemRow>(
          `INSERT INTO vault_items (user_id, encrypted_data, nonce) VALUES ($1, $2, $3)
           RETURNING ${ITEM_COLUMNS}`,
          [request.userId, encryptedData, nonce],
        );
        reply.code(201);
        return toItemResponse(rows[0]!);
      } catch (error) {
        if (isUniqueViolation(error)) throw conflict(NONCE_REUSE_MESSAGE);
        throw error;
      }
    },
  );

  app.put<{ Params: { id: string }; Body: ItemBody }>(
    '/vault-items/:id',
    {
      onRequest: authenticate,
      schema: {
        params: itemIdParamsSchema,
        body: itemBodySchema,
        response: { 200: itemResponseSchema },
      },
    },
    async (request) => {
      const { encryptedData, nonce } = decodeItem(request.body);
      let rows: ItemRow[];
      try {
        // Reject re-encrypting new content under the item's current nonce.
        // Resending the identical (ciphertext, nonce) pair is a harmless retry.
        ({ rows } = await pool.query<ItemRow>(
          `UPDATE vault_items SET encrypted_data = $3, nonce = $4, updated_at = now()
           WHERE id = $1 AND user_id = $2 AND (nonce <> $4 OR encrypted_data = $3)
           RETURNING ${ITEM_COLUMNS}`,
          [request.params.id, request.userId, encryptedData, nonce],
        ));
      } catch (error) {
        if (isUniqueViolation(error)) throw conflict(NONCE_REUSE_MESSAGE);
        throw error;
      }
      const row = rows[0];
      if (row) return toItemResponse(row);

      const { rowCount } = await pool.query(
        'SELECT 1 FROM vault_items WHERE id = $1 AND user_id = $2',
        [request.params.id, request.userId],
      );
      // Other users' items are indistinguishable from missing ones.
      throw rowCount ? conflict(NONCE_REUSE_MESSAGE) : notFound();
    },
  );

  app.delete<{ Params: { id: string } }>(
    '/vault-items/:id',
    { onRequest: authenticate, schema: { params: itemIdParamsSchema } },
    async (request, reply) => {
      const { rowCount } = await pool.query(
        'DELETE FROM vault_items WHERE id = $1 AND user_id = $2',
        [request.params.id, request.userId],
      );
      if (!rowCount) throw notFound();
      return reply.code(204).send();
    },
  );
}
