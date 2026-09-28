import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type pg from 'pg';
import type { Config } from './config.js';
import { forbidden, tooManyRequests } from './http-errors.js';
import { clearLoginFailures, refundLoginAttempt, reserveLoginAttempt } from './login-throttle.js';
import { authHashMatches } from './tokens.js';
import { decryptTotpSecret } from './totp-secret-box.js';
import { hashRecoveryCode, verifyTotp } from './totp.js';
import { authenticationOptions, verifyAssertion } from './webauthn.js';

export interface SecondFactor {
  totp_code?: string;
  recovery_code?: string;
  /** A passkey assertion (navigator.credentials.get() result, as JSON). */
  webauthn?: AuthenticationResponseJSON;
}

export type SecondFactorMethod = 'webauthn' | 'totp' | 'recovery_code';

/** Which second factors an account has, and which of them count. */
export interface SecondFactorState {
  totpEnabled: boolean;
  passkeys: number;
  /** "Require passkey": TOTP codes don't count, for login or re-authentication. */
  passkeyRequired: boolean;
}

type Db = pg.Pool | pg.PoolClient;

export async function loadSecondFactorState(db: Db, userId: string): Promise<SecondFactorState> {
  const { rows } = await db.query<{
    totp_enabled: boolean;
    passkeys: number;
    webauthn_required: boolean;
  }>(
    `SELECT totp_secret IS NOT NULL AS totp_enabled, webauthn_required,
       (SELECT count(*)::int FROM webauthn_credentials WHERE user_id = users.id) AS passkeys
     FROM users WHERE id = $1`,
    [userId],
  );
  const row = rows[0]!;
  return {
    totpEnabled: row.totp_enabled,
    passkeys: row.passkeys,
    passkeyRequired: row.webauthn_required,
  };
}

export const secondFactorEnabled = (state: SecondFactorState): boolean =>
  state.totpEnabled || state.passkeys > 0;

const totpAccepted = (state: SecondFactorState): boolean =>
  state.totpEnabled && !state.passkeyRequired;

/** The factors that would be accepted right now; recovery codes always are. */
export function secondFactorMethods(state: SecondFactorState): SecondFactorMethod[] {
  return [
    ...(state.passkeys > 0 ? (['webauthn'] as const) : []),
    ...(totpAccepted(state) ? (['totp'] as const) : []),
    'recovery_code',
  ];
}

export function secondFactorPrompt(state: SecondFactorState): string {
  if (state.passkeys > 0 && totpAccepted(state)) {
    return 'Use your passkey, or enter the 6-digit code from your authenticator app.';
  }
  if (state.passkeys > 0) return 'Use your passkey, or one of your recovery codes.';
  if (totpAccepted(state)) return 'Enter the 6-digit code from your authenticator app.';
  return 'Enter one of your recovery codes.';
}

/**
 * Machine-readable fields for a "second factor needed" reply: which methods
 * work and, if the account has passkeys, fresh WebAuthn options for
 * `purpose`. `totp_required` is kept as the "a second factor is needed"
 * flag that older clients look for. Only ever sent once the password is
 * proven.
 */
export async function secondFactorDetails(
  db: Db,
  config: Config,
  userId: string,
  state: SecondFactorState,
  purpose: 'login' | 'reauth',
): Promise<Record<string, unknown>> {
  return {
    totp_required: true,
    second_factor_methods: secondFactorMethods(state),
    ...(state.passkeys > 0 && {
      webauthn_options: await authenticationOptions(db, config.webauthn, userId, purpose),
    }),
  };
}

export type SecondFactorCheck = { ok: true } | { ok: false; message: string };

const WRONG_CODE = 'That two-factor code is incorrect or was already used.';

/**
 * Checks one second factor and uses it up: a TOTP time step can't be used
 * twice, a recovery code is deleted, and a passkey challenge works once. A
 * passkey is tried first, then a TOTP code, then a recovery code; only the
 * first one present is looked at.
 */
export async function checkSecondFactor(
  db: Db,
  config: Config,
  userId: string,
  state: SecondFactorState,
  factor: SecondFactor,
  purpose: 'login' | 'reauth',
): Promise<SecondFactorCheck> {
  if (factor.webauthn) {
    if (state.passkeys === 0) return { ok: false, message: 'This account has no passkeys.' };
    const result = await verifyAssertion(db, config.webauthn, userId, purpose, factor.webauthn);
    if (result === 'ok') return { ok: true };
    if (result === 'counter_regression') {
      return {
        ok: false,
        message:
          'This passkey’s signature counter went backwards, which can mean it was copied. Use another passkey or a recovery code, then remove this one.',
      };
    }
    return { ok: false, message: 'That passkey wasn’t accepted. Try again.' };
  }
  if (factor.totp_code) {
    if (state.totpEnabled && state.passkeyRequired) {
      return {
        ok: false,
        message: 'This account requires a passkey. Use your passkey or a recovery code.',
      };
    }
    return (await consumeTotpCode(db, config, userId, factor.totp_code))
      ? { ok: true }
      : { ok: false, message: WRONG_CODE };
  }
  if (factor.recovery_code) {
    const { rowCount } = await db.query(
      'DELETE FROM totp_recovery_codes WHERE user_id = $1 AND code_hash = $2',
      [userId, hashRecoveryCode(factor.recovery_code)],
    );
    return rowCount === 1 ? { ok: true } : { ok: false, message: WRONG_CODE };
  }
  return { ok: false, message: WRONG_CODE };
}

async function consumeTotpCode(
  db: Db,
  config: Config,
  userId: string,
  code: string,
): Promise<boolean> {
  const { rows } = await db.query<{ totp_secret: Buffer | null; totp_last_step: string }>(
    'SELECT totp_secret, totp_last_step FROM users WHERE id = $1',
    [userId],
  );
  const stored = rows[0]?.totp_secret;
  if (!stored) return false;
  // A secret that won't decrypt throws (a 500), rather than counting as a
  // wrong code: it means a misconfigured key or a tampered row, not a user error.
  const secret = decryptTotpSecret(config.totpKeys, userId, 'active', stored);
  let step: number | null;
  try {
    step = verifyTotp(secret, code, Number(rows[0]!.totp_last_step));
  } finally {
    secret.fill(0);
  }
  if (step === null) return false;
  // Conditional, so two concurrent requests can't both use the same code.
  const { rowCount } = await db.query(
    'UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2',
    [userId, step],
  );
  return rowCount === 1;
}

export const hasSecondFactor = (factor: SecondFactor): boolean =>
  Boolean(factor.webauthn || factor.totp_code || factor.recovery_code);

/**
 * For account changes from a signed-in session: re-checks the master
 * password (its auth hash) and, when `requireSecondFactor` is set and the
 * account has a second factor, one of those too (a passkey, a TOTP code
 * unless "require passkey" is on, or a recovery code). Wrong answers count
 * toward the same per-account budget as failed logins, so a stolen session
 * token isn't an unthrottled guessing oracle. Throws 403 (or 429) on failure.
 */
export async function verifyCurrentUser(
  pool: pg.Pool,
  config: Config,
  userId: string,
  body: SecondFactor & { current_auth_hash: Buffer },
  { requireSecondFactor }: { requireSecondFactor: boolean },
): Promise<{ email: string; secondFactor: SecondFactorState }> {
  const { rows } = await pool.query<{ email: string; auth_hash: Buffer }>(
    'SELECT email, auth_hash FROM users WHERE id = $1',
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
  const state = await loadSecondFactorState(pool, userId);
  if (requireSecondFactor && secondFactorEnabled(state)) {
    if (!hasSecondFactor(body)) {
      await refundLoginAttempt(pool, user.email);
      throw forbidden(
        secondFactorPrompt(state),
        await secondFactorDetails(pool, config, userId, state, 'reauth'),
      );
    }
    const check = await checkSecondFactor(pool, config, userId, state, body, 'reauth');
    if (!check.ok) {
      throw forbidden(check.message, {
        ...(await secondFactorDetails(pool, config, userId, state, 'reauth')),
        attempts_remaining: attempt.attemptsRemaining,
      });
    }
  }
  await clearLoginFailures(pool, user.email);
  return { email: user.email, secondFactor: state };
}
