import {
  AAD_ITEM,
  AAD_ITEM_LEGACY,
  AAD_VAULT_KEY,
  KEY_BYTES,
  NONCE_BYTES,
  TAG_BYTES,
} from './constants.js';
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

/**
 * What an item's ciphertext is bound to. Both values go into the AAD, so a
 * ciphertext only decrypts as the item and revision it was written for: the
 * server can't swap two items' contents, or relabel an old ciphertext as a
 * newer revision.
 */
export interface ItemBinding {
  /** The item's UUID, chosen by the client before the first save. */
  itemId: string;
  /**
   * Starts at 1 and goes up by one on every save. Revision 0 marks an item
   * saved before binding existed; those can be decrypted but never written.
   */
  revision: number;
}

export const LEGACY_ITEM_REVISION = 0;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function itemAad(binding: ItemBinding, forWriting: boolean): string {
  if (typeof binding !== 'object' || binding === null) {
    throw new CryptoInputError('binding must be an object');
  }
  const { itemId, revision } = binding;
  if (typeof itemId !== 'string' || !UUID_PATTERN.test(itemId)) {
    throw new CryptoInputError('binding.itemId must be a lowercase UUID');
  }
  if (!Number.isSafeInteger(revision) || revision < LEGACY_ITEM_REVISION) {
    throw new CryptoInputError('binding.revision must be a non-negative integer');
  }
  if (revision === LEGACY_ITEM_REVISION) {
    if (forWriting) throw new CryptoInputError('binding.revision must be at least 1');
    return AAD_ITEM_LEGACY;
  }
  // Both parts are fixed-alphabet (UUID, decimal), so NUL separators are unambiguous.
  return `${AAD_ITEM}\0${itemId}\0${revision}`;
}

/** Encrypts a vault item's JSON text with XChaCha20-Poly1305 under the vault key. */
export async function encryptItem(
  plaintextJson: string,
  vaultKey: Uint8Array,
  binding: ItemBinding,
): Promise<EncryptedPayload> {
  if (typeof plaintextJson !== 'string') {
    throw new CryptoInputError('plaintextJson must be a string');
  }
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  const aad = itemAad(binding, true);
  const sodium = await getSodium();
  const plaintext = sodium.from_string(plaintextJson);
  try {
    return seal(sodium, plaintext, vaultKey, aad);
  } finally {
    sodium.memzero(plaintext);
  }
}

/**
 * Decrypts a vault item. Throws {@link DecryptionError} on a wrong key, tampered
 * data, or a ciphertext that belongs to a different item ID or revision.
 */
export async function decryptItem(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  vaultKey: Uint8Array,
  binding: ItemBinding,
): Promise<string> {
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  const aad = itemAad(binding, false);
  const sodium = await getSodium();
  const plaintext = open(sodium, ciphertext, nonce, vaultKey, aad);
  try {
    return sodium.to_string(plaintext);
  } finally {
    sodium.memzero(plaintext);
  }
}
