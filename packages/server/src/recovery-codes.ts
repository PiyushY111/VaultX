import type pg from 'pg';
import { generateRecoveryCodes, hashRecoveryCode } from './totp.js';

/**
 * Replaces the account's recovery codes with a fresh set and returns them
 * (the only time they exist in plaintext). Recovery codes back up every
 * second factor: TOTP and passkeys alike.
 */
export async function replaceRecoveryCodes(db: pg.PoolClient, userId: string): Promise<string[]> {
  const codes = generateRecoveryCodes();
  await db.query('DELETE FROM totp_recovery_codes WHERE user_id = $1', [userId]);
  await db.query(
    'INSERT INTO totp_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::bytea[])',
    [userId, codes.map(hashRecoveryCode)],
  );
  return codes;
}
