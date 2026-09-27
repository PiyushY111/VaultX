import { AAD_ITEM, AAD_VAULT_KEY, KEY_BYTES, NONCE_BYTES, TAG_BYTES } from './constants.js';
import { CryptoInputError, DecryptionError } from './errors.js';
import { getSodium } from './sodium.js';
import { assertBytes } from './validate.js';

type Sodium = Awaited<ReturnType<typeof getSodium>>;

/** Output of every encrypt function. The nonce is not secret and must be stored with the ciphertext. */
export interface EncryptedPayload {
  /** Ciphertext with the 16-byte Poly1305 tag appended. */
  ciphertext: Uint8Array;
  /** 24-byte XChaCha20 nonce, freshly random for every encryption. */
  nonce: Uint8Array;
}

function seal(
  sodium: Sodium,
  plaintext: Uint8Array,
  key: Uint8Array,
  aad: string,
): EncryptedPayload {
  // A fresh 192-bit random nonce per call; XChaCha's nonce is large enough
  // that random nonces never collide in practice.
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    sodium.from_string(aad),
    null,
    nonce,
    key,
  );
  return { ciphertext, nonce };
}

function open(
  sodium: Sodium,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  aad: string,
): Uint8Array {
  if (!(ciphertext instanceof Uint8Array)) {
    throw new CryptoInputError('ciphertext must be a Uint8Array');
  }
  assertBytes(nonce, NONCE_BYTES, 'nonce');
  if (ciphertext.length < TAG_BYTES) {
    throw new DecryptionError();
  }
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      sodium.from_string(aad),
      nonce,
      key,
    );
  } catch {
    throw new DecryptionError();
  }
}

/** Generates a random 32-byte vault key from libsodium's CSPRNG. */
export async function generateVaultKey(): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
}

/** Wraps the vault key under the stretched master key. */
export async function encryptVaultKey(
  vaultKey: Uint8Array,
  stretchedMasterKey: Uint8Array,
): Promise<EncryptedPayload> {
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  assertBytes(stretchedMasterKey, KEY_BYTES, 'stretchedMasterKey');
  const sodium = await getSodium();
  return seal(sodium, vaultKey, stretchedMasterKey, AAD_VAULT_KEY);
}

/** Unwraps the vault key. Throws {@link DecryptionError} on a wrong key or tampered data. */
export async function decryptVaultKey(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  stretchedMasterKey: Uint8Array,
): Promise<Uint8Array> {
  assertBytes(stretchedMasterKey, KEY_BYTES, 'stretchedMasterKey');
  const sodium = await getSodium();
  const vaultKey = open(sodium, ciphertext, nonce, stretchedMasterKey, AAD_VAULT_KEY);
  if (vaultKey.length !== KEY_BYTES) {
    sodium.memzero(vaultKey);
    throw new DecryptionError();
  }
  return vaultKey;
}

/** Encrypts a vault item's JSON text with XChaCha20-Poly1305 under the vault key. */
export async function encryptItem(
  plaintextJson: string,
  vaultKey: Uint8Array,
): Promise<EncryptedPayload> {
  if (typeof plaintextJson !== 'string') {
    throw new CryptoInputError('plaintextJson must be a string');
  }
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  const sodium = await getSodium();
  const plaintext = sodium.from_string(plaintextJson);
  try {
    return seal(sodium, plaintext, vaultKey, AAD_ITEM);
  } finally {
    sodium.memzero(plaintext);
  }
}

/** Decrypts a vault item. Throws {@link DecryptionError} on a wrong key or tampered data. */
export async function decryptItem(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  vaultKey: Uint8Array,
): Promise<string> {
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  const sodium = await getSodium();
  const plaintext = open(sodium, ciphertext, nonce, vaultKey, AAD_ITEM);
  try {
    return sodium.to_string(plaintext);
  } finally {
    sodium.memzero(plaintext);
  }
}
