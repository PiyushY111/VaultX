import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

/**
 * TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30-second steps — what every
 * authenticator app supports — plus one-time recovery codes.
 */

export const TOTP_SECRET_BYTES = 20;
const STEP_SECONDS = 30;
const DIGITS = 6;
/** Codes from one step either side are accepted, for clock drift. */
const DRIFT_STEPS = 1;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32[(value << (5 - bits)) & 31];
  return output;
}

export const generateTotpSecret = (): Buffer => randomBytes(TOTP_SECRET_BYTES);

/** HOTP (RFC 4226) for one counter value. */
export function hotp(secret: Buffer, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', secret).update(message).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

export const timeStep = (nowMs: number): number => Math.floor(nowMs / 1000 / STEP_SECONDS);

/**
 * Returns the time step `code` is valid for, or null. Steps at or before
 * `lastUsedStep` are refused, so each code works once.
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  lastUsedStep: number,
  nowMs = Date.now(),
): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = timeStep(nowMs);
  let matched: number | null = null;
  // Check every candidate (no early exit), comparing in constant time.
  for (let step = current - DRIFT_STEPS; step <= current + DRIFT_STEPS; step++) {
    const expected = Buffer.from(hotp(secret, step));
    if (timingSafeEqual(expected, Buffer.from(code)) && step > lastUsedStep) matched ??= step;
  }
  return matched;
}

export function otpauthUri(email: string, secret: Buffer): string {
  const label = encodeURIComponent(`VaultX:${email}`);
  const params = new URLSearchParams({
    secret: base32Encode(secret),
    issuer: 'VaultX',
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params}`;
}

// Recovery codes: 10 characters from an alphabet without look-alikes
// (about 50 bits each), shown as XXXXX-XXXXX.
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const RECOVERY_CODE_COUNT = 10;

export function generateRecoveryCodes(): string[] {
  return Array.from({ length: RECOVERY_CODE_COUNT }, () => {
    const chars = Array.from({ length: 10 }, () => RECOVERY_ALPHABET[randomInt(32)]).join('');
    return `${chars.slice(0, 5)}-${chars.slice(5)}`;
  });
}

/** Case, spaces and dashes don't matter when a code is typed back in. */
export const normalizeRecoveryCode = (code: string): string =>
  code.toUpperCase().replace(/[\s-]/g, '');

export const hashRecoveryCode = (code: string): Buffer =>
  createHash('sha256')
    .update('password-manager:server:recovery-code:v1\0')
    .update(normalizeRecoveryCode(code))
    .digest();
