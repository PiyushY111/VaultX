import type pg from 'pg';
import { withTransaction } from './db.js';
import {
  ENCRYPTED_TOTP_SECRET_BYTES,
  LEGACY_TOTP_SECRET_BYTES,
  decryptTotpSecret,
  encryptTotpSecret,
  isCurrentTotpCiphertext,
  type TotpKeyring,
  type TotpSecretPurpose,
} from './totp-secret-box.js';

/**
 * - `legacy`: encrypt the plaintext secrets written before migration 005.
 *   Run at every startup; a no-op once there are none.
 * - `rotate`: also re-encrypt everything not yet under the primary key
 *   (`npm run rotate-totp-key`).
 */
export type ReencryptMode = 'legacy' | 'rotate';

export interface ReencryptResult {
  /** Accounts whose secrets were rewritten. */
  updated: number;
  /** Accounts whose secrets couldn't be decrypted, and so were left alone. */
  failed: { userId: string; error: string }[];
}

const BATCH_SIZE = 100;

const COLUMNS: { column: 'totp_secret' | 'totp_pending_secret'; purpose: TotpSecretPurpose }[] = [
  { column: 'totp_secret', purpose: 'active' },
  { column: 'totp_pending_secret', purpose: 'pending' },
];

const needsWork = (keyring: TotpKeyring, mode: ReencryptMode, stored: Buffer | null): boolean =>
  stored !== null &&
  (mode === 'legacy'
    ? stored.length === LEGACY_TOTP_SECRET_BYTES
    : !isCurrentTotpCiphertext(keyring, stored));

function candidateFilter(column: string): Record<ReencryptMode, string> {
  return {
    legacy: `octet_length(${column}) = ${LEGACY_TOTP_SECRET_BYTES}`,
    rotate: `(${column} IS NOT NULL AND (octet_length(${column}) <> ${ENCRYPTED_TOTP_SECRET_BYTES}
              OR get_byte(${column}, 0) <> $2))`,
  };
}

/**
 * Rewrites the secrets `mode` selects. Idempotent and safe to run while the
 * server is serving, or from several instances at once: each account is
 * re-read under a row lock before it's rewritten, so a secret that another
 * run (or a request) already changed is left as it is.
 */
export async function reencryptTotpSecrets(
  pool: pg.Pool,
  keyring: TotpKeyring,
  mode: ReencryptMode,
): Promise<ReencryptResult> {
  const where = COLUMNS.map(({ column }) => candidateFilter(column)[mode]).join(' OR ');
  const result: ReencryptResult = { updated: 0, failed: [] };
  // Page by id rather than re-running the query until it's empty, so rows
  // that fail to decrypt can't make this loop forever.
  let after = '00000000-0000-0000-0000-000000000000';
  for (;;) {
    const params: unknown[] = [after];
    if (mode === 'rotate') params.push(keyring.primary.id);
    const { rows } = await pool.query<{ id: string }>(
      `SELECT id FROM users WHERE id > $1 AND (${where}) ORDER BY id LIMIT ${BATCH_SIZE}`,
      params,
    );
    for (const { id } of rows) {
      try {
        if (await reencryptUser(pool, keyring, mode, id)) result.updated++;
      } catch (error) {
        result.failed.push({ userId: id, error: (error as Error).message });
      }
    }
    if (rows.length < BATCH_SIZE) return result;
    after = rows[rows.length - 1]!.id;
  }
}

async function reencryptUser(
  pool: pg.Pool,
  keyring: TotpKeyring,
  mode: ReencryptMode,
  userId: string,
): Promise<boolean> {
  return withTransaction(pool, async (db) => {
    const { rows } = await db.query<{
      totp_secret: Buffer | null;
      totp_pending_secret: Buffer | null;
    }>('SELECT totp_secret, totp_pending_secret FROM users WHERE id = $1 FOR UPDATE', [userId]);
    const row = rows[0];
    if (!row) return false; // Deleted since it was listed.

    const updates: Partial<Record<(typeof COLUMNS)[number]['column'], Buffer>> = {};
    for (const { column, purpose } of COLUMNS) {
      const stored = row[column];
      if (!stored || !needsWork(keyring, mode, stored)) continue;
      const secret = decryptTotpSecret(keyring, userId, purpose, stored);
      try {
        updates[column] = encryptTotpSecret(keyring, userId, purpose, secret);
      } finally {
        secret.fill(0);
      }
    }
    const entries = Object.entries(updates);
    if (entries.length === 0) return false;
    const assignments = entries.map(([column], i) => `${column} = $${i + 2}`).join(', ');
    await db.query(`UPDATE users SET ${assignments} WHERE id = $1`, [
      userId,
      ...entries.map(([, value]) => value),
    ]);
    return true;
  });
}

/**
 * Key ids found in stored secrets that the keyring can't decrypt, with how
 * many accounts use each. Non-empty means a key was removed from
 * TOTP_ENCRYPTION_KEY before every secret was rotated off it.
 */
export async function findUnknownTotpKeyIds(
  pool: pg.Pool,
  keyring: TotpKeyring,
): Promise<{ keyId: number; accounts: number }[]> {
  const { rows } = await pool.query<{ key_id: number; accounts: number }>(
    `SELECT key_id, count(DISTINCT id)::int AS accounts FROM (
       SELECT id, get_byte(totp_secret, 0) AS key_id FROM users
       WHERE octet_length(totp_secret) = ${ENCRYPTED_TOTP_SECRET_BYTES}
       UNION ALL
       SELECT id, get_byte(totp_pending_secret, 0) FROM users
       WHERE octet_length(totp_pending_secret) = ${ENCRYPTED_TOTP_SECRET_BYTES}
     ) stored
     WHERE key_id <> ALL($1::int[])
     GROUP BY key_id ORDER BY key_id`,
    [[...keyring.byId.keys()]],
  );
  return rows.map((row) => ({ keyId: row.key_id, accounts: row.accounts }));
}

/**
 * Startup step: encrypt any legacy plaintext secrets, and refuse to start if
 * some secrets are under a key that's no longer configured (those accounts
 * couldn't log in, and the fix — putting the old key back — is the
 * operator's to make).
 */
export async function prepareTotpSecrets(
  pool: pg.Pool,
  keyring: TotpKeyring,
): Promise<ReencryptResult> {
  const result = await reencryptTotpSecrets(pool, keyring, 'legacy');
  if (result.failed.length) {
    throw new Error(
      `Could not encrypt the legacy two-factor secrets of ${result.failed.length} account(s): ${result.failed[0]!.error}`,
    );
  }
  const unknown = await findUnknownTotpKeyIds(pool, keyring);
  if (unknown.length) {
    const summary = unknown.map((u) => `key id ${u.keyId} (${u.accounts} account(s))`).join(', ');
    throw new Error(
      `Some two-factor secrets are encrypted under keys missing from TOTP_ENCRYPTION_KEY: ${summary}. ` +
        'Add the old key back after the new one, start the server, and run `npm run rotate-totp-key` before removing it.',
    );
  }
  return result;
}
