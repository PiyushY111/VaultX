import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { KDF_SALT_BYTES } from './limits.js';

const SESSION_TOKEN_BYTES = 32;
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function sha256(...parts: (string | Buffer)[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

/**
 * Server-side hash of the client's authHash, stored in `users.auth_hash`.
 *
 * The authHash is a uniformly random 32-byte HKDF output, so a fast hash
 * suffices: there is no low-entropy input to brute-force. What this prevents
 * is replaying a leaked `users.auth_hash` value to log in.
 */
export function hashAuthHash(authHash: Buffer): Buffer {
  return sha256('password-manager:server:auth-hash:v1\0', authHash);
}

/** Constant-time check of a submitted authHash against the stored hash. */
export function authHashMatches(submitted: Buffer, storedHash: Buffer): boolean {
  const candidate = hashAuthHash(submitted);
  return candidate.length === storedHash.length && timingSafeEqual(candidate, storedHash);
}

/** A placeholder stored hash, compared against for unknown emails so login timing doesn't reveal them. */
export const DUMMY_AUTH_HASH = hashAuthHash(randomBytes(32));

/** Creates a bearer token for the client and the hash to store in `sessions.token_hash`. */
export function generateSessionToken(): { token: string; tokenHash: Buffer } {
  const raw = randomBytes(SESSION_TOKEN_BYTES);
  return { token: raw.toString('base64url'), tokenHash: sha256(raw) };
}

/** Hashes a presented bearer token for lookup, or returns null if it is malformed. */
export function hashSessionToken(token: string): Buffer | null {
  if (!SESSION_TOKEN_PATTERN.test(token)) return null;
  const raw = Buffer.from(token, 'base64url');
  return raw.length === SESSION_TOKEN_BYTES ? sha256(raw) : null;
}

/** Deterministic fake KDF salt for an unknown email, stable across requests. */
export function fakeKdfSalt(secret: Buffer, email: string): Buffer {
  return createHmac('sha256', secret)
    .update(`prelogin-salt:${email}`)
    .digest()
    .subarray(0, KDF_SALT_BYTES);
}
