import type pg from 'pg';

/**
 * Per-account limit on failed logins: at most `maxFailures` unsuccessful
 * attempts per email per fixed window. It complements the per-IP rate limit,
 * which can't stop a distributed guessing attack against one account.
 *
 * Each attempt is counted *before* the auth hash is checked, in a single
 * atomic upsert, so concurrent requests can't slip past the limit; a
 * successful login then clears the count. Once the limit is reached, further
 * attempts are refused without checking the auth hash (so even the correct
 * password gets a 429 until the window ends), and the response says how long
 * to wait. Extra attempts don't extend the window.
 *
 * Trade-off: anyone who knows an email can lock that account out for one
 * window. The window is short, lockout is never permanent, and the error
 * explains what happened. See THREAT_MODEL.md.
 */

export interface LoginThrottleConfig {
  maxFailures: number;
  windowSeconds: number;
}

export type LoginAttempt =
  { allowed: true; attemptsRemaining: number } | { allowed: false; retryAfterSeconds: number };

export async function reserveLoginAttempt(
  pool: pg.Pool,
  email: string,
  { maxFailures, windowSeconds }: LoginThrottleConfig,
): Promise<LoginAttempt> {
  // Opportunistic cleanup keeps the table small without a background job.
  await pool.query(
    'DELETE FROM login_failures WHERE window_started_at <= now() - make_interval(secs => $1)',
    [windowSeconds],
  );
  const { rows } = await pool.query<{ failure_count: number; retry_after_seconds: string }>(
    `INSERT INTO login_failures AS lf (email, failure_count, window_started_at)
     VALUES ($1, 1, now())
     ON CONFLICT (email) DO UPDATE SET
       failure_count = CASE
         WHEN lf.window_started_at <= now() - make_interval(secs => $2) THEN 1
         ELSE lf.failure_count + 1
       END,
       window_started_at = CASE
         WHEN lf.window_started_at <= now() - make_interval(secs => $2) THEN now()
         ELSE lf.window_started_at
       END
     RETURNING
       failure_count,
       EXTRACT(EPOCH FROM lf.window_started_at + make_interval(secs => $2) - now()) AS retry_after_seconds`,
    [email, windowSeconds],
  );
  const row = rows[0]!;
  if (row.failure_count > maxFailures) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil(Number(row.retry_after_seconds))),
    };
  }
  // If this attempt fails, this many remain in the window.
  return { allowed: true, attemptsRemaining: maxFailures - row.failure_count };
}

export async function clearLoginFailures(pool: pg.Pool, email: string): Promise<void> {
  await pool.query('DELETE FROM login_failures WHERE email = $1', [email]);
}

/**
 * Gives back one reserved attempt, for a request that proved the password
 * but still needs its second factor. (Clearing the count instead would let
 * someone who knows the password reset the budget for guessing codes.)
 */
export async function refundLoginAttempt(pool: pg.Pool, email: string): Promise<void> {
  await pool.query(
    `WITH refunded AS (
       UPDATE login_failures SET failure_count = failure_count - 1
       WHERE email = $1 AND failure_count > 1
       RETURNING email
     )
     DELETE FROM login_failures
     WHERE email = $1 AND failure_count = 1 AND NOT EXISTS (SELECT 1 FROM refunded)`,
    [email],
  );
}
