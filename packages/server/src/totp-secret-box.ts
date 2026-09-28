import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { TOTP_SECRET_BYTES } from './totp.js';

/**
 * Encryption at rest for the two-factor secrets in `users.totp_secret` and
 * `users.totp_pending_secret`.
 *
 * The server has to be able to read these secrets to check codes, so this is
 * not zero-knowledge: the key sits in the server's environment
 * (TOTP_ENCRYPTION_KEY). What it buys is that a copy of the database alone —
 * a leaked dump, a stolen backup, read-only SQL injection — no longer hands
 * over every user's second factor. Someone who also has the server's
 * environment has the key.
 *
 * Stored format (49 bytes):
 *
 *   key id (1) ‖ nonce (12) ‖ AES-256-GCM ciphertext (20) ‖ tag (16)
 *
 * The AAD binds each ciphertext to its user and column, so a row can't be
 * copied to another account, or a pending secret promoted to the active one,
 * by editing the database.
 */

// Domain-separation labels. Changing either one makes every stored secret
// undecryptable — add a new version instead. These live here rather than in
// packages/crypto/src/constants.ts because that package is the client's
// libsodium code; the server doesn't load it at runtime.
export const AAD_TOTP_SECRET = 'password-manager:server:totp:v1';
const KEY_ID_LABEL = 'password-manager:server:totp-key-id:v1';

export const TOTP_KEY_BYTES = 32;
const KEY_ID_BYTES = 1;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
export const ENCRYPTED_TOTP_SECRET_BYTES =
  KEY_ID_BYTES + NONCE_BYTES + TOTP_SECRET_BYTES + TAG_BYTES;
/** Secrets written before migration 005 were stored as the raw 20 bytes. */
export const LEGACY_TOTP_SECRET_BYTES = TOTP_SECRET_BYTES;

/** Which column a secret lives in; part of the AAD. */
export type TotpSecretPurpose = 'active' | 'pending';

export interface TotpKey {
  id: number;
  key: Buffer;
}

export interface TotpKeyring {
  /** Encrypts every new secret. */
  primary: TotpKey;
  /** Every configured key by id, primary included; any of them can decrypt. */
  byId: ReadonlyMap<number, Buffer>;
}

/** Thrown when a stored secret can't be decrypted. The message never contains key or secret bytes. */
export class TotpSecretDecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TotpSecretDecryptionError';
  }
}

// Exactly 32 bytes of standard, padded base64 (what `openssl rand -base64 32` prints).
const BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/;

/**
 * The key id is derived from the key, not its position in the list, so it
 * stays the same when a new key is put in front during rotation. It is one
 * byte of a hash of the key: 8 bits, which says nothing useful about a
 * 256-bit key.
 */
export const totpKeyId = (key: Buffer): number =>
  createHash('sha256').update(`${KEY_ID_LABEL}\0`).update(key).digest()[0]!;

/**
 * Parses TOTP_ENCRYPTION_KEY: one or more comma-separated base64 keys, each
 * exactly 32 bytes. The first encrypts; all of them decrypt. Errors name the
 * position of a bad key but never echo its value.
 */
export function parseTotpKeyring(raw: string | undefined): TotpKeyring {
  const name = 'TOTP_ENCRYPTION_KEY';
  if (raw === undefined || raw.trim() === '') {
    throw new Error(
      `${name} is not set. Generate one with: openssl rand -base64 32 (see .env.example).`,
    );
  }
  const entries = raw.split(',').map((entry) => entry.trim());
  const keys = entries.map((entry, index) => {
    const position = `${name} key #${index + 1}`;
    if (!BASE64_KEY.test(entry)) {
      throw new Error(
        `${position} must be exactly ${TOTP_KEY_BYTES} bytes, base64-encoded (openssl rand -base64 32).`,
      );
    }
    const key = Buffer.from(entry, 'base64');
    if (key.every((byte) => byte === 0)) throw new Error(`${position} is all zero bytes.`);
    return { id: totpKeyId(key), key };
  });

  const byId = new Map<number, Buffer>();
  for (const [index, { id, key }] of keys.entries()) {
    const existing = byId.get(id);
    if (existing) {
      throw new Error(
        existing.equals(key)
          ? `${name} lists the same key twice (key #${index + 1}).`
          : `${name} key #${index + 1} has the same key id as an earlier key; generate a different new key.`,
      );
    }
    byId.set(id, key);
  }
  return { primary: keys[0]!, byId };
}

function aad(keyId: number, userId: string, purpose: TotpSecretPurpose): Buffer {
  // NUL separators: none of the parts can contain one, so the encoding is unambiguous.
  return Buffer.concat([
    Buffer.from(`${AAD_TOTP_SECRET}\0${userId}\0${purpose}\0`, 'utf8'),
    Buffer.from([keyId]),
  ]);
}

export function encryptTotpSecret(
  keyring: TotpKeyring,
  userId: string,
  purpose: TotpSecretPurpose,
  secret: Buffer,
): Buffer {
  if (secret.length !== TOTP_SECRET_BYTES) {
    throw new Error(`TOTP secret must be ${TOTP_SECRET_BYTES} bytes`);
  }
  const { id, key } = keyring.primary;
  // Random 96-bit nonces: far below the ~2^32 messages per key where GCM
  // nonce collisions become a concern, given one secret per account.
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad(id, userId, purpose));
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  return Buffer.concat([Buffer.from([id]), nonce, ciphertext, cipher.getAuthTag()]);
}

/**
 * Returns the plaintext secret. The caller should zero it (`fill(0)`) once
 * it's done with it. A 20-byte value is a legacy plaintext secret from before
 * migration 005 and is returned as a copy; the server re-encrypts those at
 * startup (see reencryptTotpSecrets), so they only exist briefly.
 */
export function decryptTotpSecret(
  keyring: TotpKeyring,
  userId: string,
  purpose: TotpSecretPurpose,
  stored: Buffer,
): Buffer {
  if (stored.length === LEGACY_TOTP_SECRET_BYTES) return Buffer.from(stored);
  if (stored.length !== ENCRYPTED_TOTP_SECRET_BYTES) {
    throw new TotpSecretDecryptionError(
      `Stored TOTP secret has unexpected length ${stored.length}`,
    );
  }
  const keyId = stored[0]!;
  const key = keyring.byId.get(keyId);
  if (!key) {
    throw new TotpSecretDecryptionError(
      `Stored TOTP secret uses key id ${keyId}, which is not in TOTP_ENCRYPTION_KEY`,
    );
  }
  const nonce = stored.subarray(KEY_ID_BYTES, KEY_ID_BYTES + NONCE_BYTES);
  const ciphertext = stored.subarray(KEY_ID_BYTES + NONCE_BYTES, stored.length - TAG_BYTES);
  const tag = stored.subarray(stored.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(aad(keyId, userId, purpose));
  decipher.setAuthTag(tag);
  const plaintext = decipher.update(ciphertext);
  try {
    decipher.final();
  } catch {
    plaintext.fill(0);
    throw new TotpSecretDecryptionError(
      'Stored TOTP secret failed authentication (wrong key, wrong user or column, or tampered)',
    );
  }
  return plaintext;
}

/** True when `stored` is already encrypted under the keyring's primary key. */
export const isCurrentTotpCiphertext = (keyring: TotpKeyring, stored: Buffer): boolean =>
  stored.length === ENCRYPTED_TOTP_SECRET_BYTES && stored[0] === keyring.primary.id;
