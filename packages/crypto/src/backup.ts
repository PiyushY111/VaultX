import { AAD_BACKUP, KEY_BYTES, NONCE_BYTES, TAG_BYTES } from './constants.js';
import { CryptoInputError, DecryptionError } from './errors.js';
import { getSodium } from './sodium.js';
import { assertBytes } from './validate.js';
import type { EncryptedPayload } from './aead.js';

/**
 * Encrypts an exported backup (the vault's items as JSON) under a key the
 * client derived from a backup password with Argon2id and a fresh salt, so
 * the file opens anywhere with just that password. Its own AAD label means a
 * backup can't be passed off as an item, a manifest or a wrapped vault key.
 */
export async function encryptBackup(
  json: string,
  backupKey: Uint8Array,
): Promise<EncryptedPayload> {
  if (typeof json !== 'string') throw new CryptoInputError('json must be a string');
  assertBytes(backupKey, KEY_BYTES, 'backupKey');
  const sodium = await getSodium();
  const plaintext = sodium.from_string(json);
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  try {
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      sodium.from_string(AAD_BACKUP),
      null,
      nonce,
      backupKey,
    );
    return { ciphertext, nonce };
  } finally {
    sodium.memzero(plaintext);
  }
}

/** Throws {@link DecryptionError} for a wrong password (key) or a damaged file. */
export async function decryptBackup(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  backupKey: Uint8Array,
): Promise<string> {
  assertBytes(backupKey, KEY_BYTES, 'backupKey');
  assertBytes(nonce, NONCE_BYTES, 'nonce');
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < TAG_BYTES) {
    throw new DecryptionError();
  }
  const sodium = await getSodium();
  let plaintext: Uint8Array;
  try {
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      sodium.from_string(AAD_BACKUP),
      nonce,
      backupKey,
    );
  } catch {
    throw new DecryptionError();
  }
  try {
    return sodium.to_string(plaintext);
  } finally {
    sodium.memzero(plaintext);
  }
}
