import { KEY_BYTES, SALT_BYTES } from './constants.js';
import { CryptoInputError } from './errors.js';
import { getSodium } from './sodium.js';
import { assertBytes } from './validate.js';

/**
 * Argon2id cost parameters. Store these alongside each user's salt so they can
 * be raised for new accounts (or on re-key) without breaking existing users.
 */
export interface KdfParams {
  /** Memory cost in KiB (Argon2 `m`). */
  memoryCost: number;
  /** Number of passes over memory (Argon2 `t`). */
  iterations: number;
  /**
   * Degree of parallelism (Argon2 `p`). libsodium's Argon2id implementation is
   * single-lane, so only `1` is currently accepted. The field exists so stored
   * params are forward-compatible with a future multi-lane implementation.
   */
  parallelism: number;
}

/** Defaults for new accounts: 64 MiB, 3 passes, 1 lane. */
export const DEFAULT_KDF_PARAMS: Readonly<KdfParams> = Object.freeze({
  memoryCost: 64 * 1024,
  iterations: 3,
  parallelism: 1,
});

/**
 * Floor below which params are rejected (OWASP minimum for Argon2id:
 * m=19 MiB, t=2, p=1). Raising this later would lock out users whose stored
 * params fall below it, so migrate those users before raising it.
 */
export const MIN_KDF_PARAMS: Readonly<KdfParams> = Object.freeze({
  memoryCost: 19 * 1024,
  iterations: 2,
  parallelism: 1,
});

/** Upper bound on memory cost (1 GiB) to keep WASM builds from failing unpredictably. */
export const MAX_KDF_MEMORY_COST = 1024 * 1024;

export function validateKdfParams(params: KdfParams): void {
  const { memoryCost, iterations, parallelism } = params;
  for (const [name, value] of Object.entries({ memoryCost, iterations, parallelism })) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new CryptoInputError(`kdfParams.${name} must be a positive integer`);
    }
  }
  if (memoryCost < MIN_KDF_PARAMS.memoryCost || memoryCost > MAX_KDF_MEMORY_COST) {
    throw new CryptoInputError(
      `kdfParams.memoryCost must be between ${MIN_KDF_PARAMS.memoryCost} and ${MAX_KDF_MEMORY_COST} KiB`,
    );
  }
  if (iterations < MIN_KDF_PARAMS.iterations) {
    throw new CryptoInputError(
      `kdfParams.iterations must be at least ${MIN_KDF_PARAMS.iterations}`,
    );
  }
  if (parallelism !== 1) {
    throw new CryptoInputError(
      'kdfParams.parallelism must be 1 (libsodium Argon2id is single-lane)',
    );
  }
}

/** Generates a random salt suitable for {@link deriveMasterKey}. */
export async function generateSalt(): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.randombytes_buf(SALT_BYTES);
}

/**
 * Derives the 32-byte master key from the user's master password with Argon2id.
 *
 * The password is Unicode-normalized to NFC before hashing so the same
 * password typed on different platforms yields the same key.
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  kdfParams: KdfParams,
): Promise<Uint8Array> {
  if (typeof password !== 'string' || password.length === 0) {
    throw new CryptoInputError('password must be a non-empty string');
  }
  assertBytes(salt, SALT_BYTES, 'salt');
  validateKdfParams(kdfParams);

  const sodium = await getSodium();
  const passwordBytes = sodium.from_string(password.normalize('NFC'));
  try {
    return sodium.crypto_pwhash(
      KEY_BYTES,
      passwordBytes,
      salt,
      kdfParams.iterations,
      kdfParams.memoryCost * 1024,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    sodium.memzero(passwordBytes);
  }
}
