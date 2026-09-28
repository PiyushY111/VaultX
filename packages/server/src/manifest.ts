import type pg from 'pg';
import { decodeBytes, encodeBytes } from './encoding.js';
import { conflict } from './http-errors.js';
import { MAX_MANIFEST_CIPHERTEXT_BYTES, NONCE_BYTES, TAG_BYTES } from './limits.js';

/**
 * The client's encrypted vault manifest (packages/crypto/src/manifest.ts).
 * The server can't read it. It only makes each write move it to exactly the
 * next version, in the same transaction as the item change, so the manifest
 * clients read always describes the items stored with it.
 */

export interface ManifestBody {
  version: number;
  encrypted_data: string;
  nonce: string;
}

export const MANIFEST_CONFLICT_MESSAGE =
  'Your vault was changed elsewhere since it was loaded. Reload it and try again.';

/**
 * Stores `manifest` if it's the next version; otherwise a 409 carrying the
 * current `manifest_version`. The row lock taken by the UPDATE serializes
 * concurrent writers to one vault.
 */
export async function advanceManifest(
  db: pg.PoolClient,
  userId: string,
  manifest: ManifestBody,
): Promise<void> {
  const encrypted = decodeBytes(manifest.encrypted_data, 'manifest.encrypted_data', {
    min: TAG_BYTES,
    max: MAX_MANIFEST_CIPHERTEXT_BYTES,
  });
  const nonce = decodeBytes(manifest.nonce, 'manifest.nonce', { exact: NONCE_BYTES });
  const { rowCount } = await db.query(
    `UPDATE users SET manifest_version = $2, encrypted_manifest = $3, manifest_nonce = $4
     WHERE id = $1 AND manifest_version = $2 - 1`,
    [userId, manifest.version, encrypted, nonce],
  );
  if (rowCount) return;
  const { rows } = await db.query<{ manifest_version: number }>(
    'SELECT manifest_version FROM users WHERE id = $1',
    [userId],
  );
  throw conflict(MANIFEST_CONFLICT_MESSAGE, { manifest_version: rows[0]?.manifest_version ?? 0 });
}

/** True if `manifest` is exactly what's stored (an identical retry of the last write). */
export async function isCurrentManifest(
  db: pg.PoolClient,
  userId: string,
  manifest: ManifestBody,
): Promise<boolean> {
  const { rows } = await db.query<{ manifest_version: number; encrypted_manifest: Buffer | null }>(
    'SELECT manifest_version, encrypted_manifest FROM users WHERE id = $1',
    [userId],
  );
  const row = rows[0];
  return (
    row?.manifest_version === manifest.version &&
    row.encrypted_manifest !== null &&
    encodeBytes(row.encrypted_manifest) === manifest.encrypted_data
  );
}

export function toManifestResponse(row: {
  manifest_version: number;
  encrypted_manifest: Buffer | null;
  manifest_nonce: Buffer | null;
}) {
  if (!row.encrypted_manifest || !row.manifest_nonce) return null;
  return {
    version: row.manifest_version,
    encrypted_data: encodeBytes(row.encrypted_manifest),
    nonce: encodeBytes(row.manifest_nonce),
  };
}
