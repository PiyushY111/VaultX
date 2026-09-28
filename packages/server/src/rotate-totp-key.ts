import { pathToFileURL } from 'node:url';
import type pg from 'pg';
import { createPool } from './db.js';
import { reencryptTotpSecrets } from './totp-reencrypt.js';
import { parseTotpKeyring } from './totp-secret-box.js';

/**
 * `npm run rotate-totp-key -w @password-manager/server`
 *
 * Re-encrypts every stored two-factor secret under the first key in
 * TOTP_ENCRYPTION_KEY (and encrypts any legacy plaintext ones). To rotate:
 *
 *   1. Put a new key in front: TOTP_ENCRYPTION_KEY=<new>,<old>
 *   2. Restart the server, so new secrets use the new key.
 *   3. Run this script with the same TOTP_ENCRYPTION_KEY.
 *   4. Once it reports no failures, remove <old> and restart again.
 *
 * Safe to run while the server is up, and safe to re-run. Returns the
 * process exit code: 0 when every secret is now under the primary key.
 */
export async function rotateTotpKey(
  pool: pg.Pool,
  env: NodeJS.ProcessEnv,
  log: { info(message: string): void; error(message: string): void },
): Promise<number> {
  const keyring = parseTotpKeyring(env.TOTP_ENCRYPTION_KEY);
  const { updated, failed } = await reencryptTotpSecrets(pool, keyring, 'rotate');
  log.info(
    `Re-encrypted two-factor secrets for ${updated} account(s) under key id ${keyring.primary.id}.`,
  );
  if (!failed.length) return 0;
  // User ids aren't secret, and the operator needs them to investigate.
  for (const { userId, error } of failed) log.error(`  ${userId}: ${error}`);
  log.error(`${failed.length} account(s) could not be re-encrypted; see above.`);
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const pool = createPool();
  try {
    process.exitCode = await rotateTotpKey(pool, process.env, {
      info: (message) => console.log(message),
      error: (message) => console.error(message),
    });
  } catch (error) {
    console.error((error as Error).message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}
