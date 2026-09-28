import type pg from 'pg';
import type { Config } from './config.js';
import { forbidden, tooManyRequests } from './http-errors.js';
import { clearLoginFailures, refundLoginAttempt, reserveLoginAttempt } from './login-throttle.js';
import { authHashMatches } from './tokens.js';
import { hashRecoveryCode, verifyTotp } from './totp.js';

export interface SecondFactor {
  totp_code?: string;
  recovery_code?: string;
}

/**
 * Checks a TOTP or recovery code for a user with two-factor enabled, and
 * uses it up: a TOTP time step can't be used twice, and a recovery code is
 * deleted. Returns false for a wrong, reused, or missing code.
 */
export async function consumeSecondFactor(
  db: pg.Pool | pg.PoolClient,
  userId: string,
  factor: SecondFactor,
): Promise<boolean> {
  if (factor.totp_code) {
    const { rows } = await db.query<{ totp_secret: Buffer | null; totp_last_step: string }>(
      'SELECT totp_secret, totp_last_step FROM users WHERE id = $1',
      [userId],
    );
    const secret = rows[0]?.totp_secret;
    if (!secret) return false;
    const step = verifyTotp(secret, factor.totp_code, Number(rows[0]!.totp_last_step));
    if (step === null) return false;
    // Conditional, so two concurrent requests can't both use the same code.
    const { rowCount } = await db.query(
      'UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2',
      [userId, step],
    );
    return rowCount === 1;
  }
  if (factor.recovery_code) {
    const { rowCount } = await db.query(
      'DELETE FROM totp_recovery_codes WHERE user_id = $1 AND code_hash = $2',
      [userId, hashRecoveryCode(factor.recovery_code)],
    );
    return rowCount === 1;
  }
  return false;
}

export const SECOND_FACTOR_REQUIRED = 'Enter the 6-digit code from your authenticator app.';

/**
 * For account changes from a signed-in session: re-checks the master
 * password (its auth hash) and, when `requireSecondFactor` is set and the
 * account has two-factor on, a code. Wrong answers count toward the same
 * per-account budget as failed logins, so a stolen session token isn't an
 * unthrottled guessing oracle. Throws 403 (or 429) on failure.
 */
export async function verifyCurrentUser(
  pool: pg.Pool,
  config: Config,
  userId: string,
  body: SecondFactor & { current_auth_hash: Buffer },
  { requireSecondFactor }: { requireSecondFactor: boolean },
): Promise<{ email: string }> {
  const { rows } = await pool.query<{ email: string; auth_hash: Buffer; totp_enabled: boolean }>(
    'SELECT email, auth_hash, totp_secret IS NOT NULL AS totp_enabled FROM users WHERE id = $1',
    [userId],
  );
  const user = rows[0]!;
  const attempt = await reserveLoginAttempt(pool, user.email, config.loginThrottle);
  if (!attempt.allowed) {
    throw tooManyRequests('Too many incorrect attempts. Try again later.', {
      retry_after_seconds: attempt.retryAfterSeconds,
    });
  }
  if (!authHashMatches(body.current_auth_hash, user.auth_hash)) {
    throw forbidden('Current master password is incorrect.', {
      attempts_remaining: attempt.attemptsRemaining,
    });
  }
  if (requireSecondFactor && user.totp_enabled) {
    if (!body.totp_code && !body.recovery_code) {
      await refundLoginAttempt(pool, user.email);
      throw forbidden(SECOND_FACTOR_REQUIRED, { totp_required: true });
    }
    if (!(await consumeSecondFactor(pool, userId, body))) {
      throw forbidden('That two-factor code is incorrect or was already used.', {
        totp_required: true,
        attempts_remaining: attempt.attemptsRemaining,
      });
    }
  }
  await clearLoginFailures(pool, user.email);
  return { email: user.email };
}
