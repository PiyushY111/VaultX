// Byte lengths and bounds for everything clients send. These mirror
// @password-manager/crypto (test/boundaries.test.ts asserts they stay in
// sync), but are duplicated so the server has no runtime dependency on the
// crypto package.

export const AUTH_HASH_BYTES = 32;
export const KDF_SALT_BYTES = 16;
export const NONCE_BYTES = 24;
export const TAG_BYTES = 16;
/** 32-byte vault key + 16-byte tag. */
export const ENCRYPTED_VAULT_KEY_BYTES = 32 + TAG_BYTES;
export const MAX_ITEM_CIPHERTEXT_BYTES = 1024 * 1024;
/** The encrypted vault manifest: roughly 50 bytes per item, so about 20,000 items. */
export const MAX_MANIFEST_CIPHERTEXT_BYTES = 1024 * 1024;
/** Large enough for a max-size item plus a max-size manifest, base64-encoded. */
export const BODY_LIMIT_BYTES = 4 * 1024 * 1024;
/**
 * A password change carries every item, re-encrypted under the new vault key.
 * Only authenticated requests get this far (the body is read after auth).
 */
export const CHANGE_PASSWORD_BODY_LIMIT_BYTES = 64 * 1024 * 1024;
/** Items per POST /vault-items/batch (an import); clients send bigger imports in several batches. */
export const MAX_BATCH_ITEMS = 500;

export interface KdfParams {
  memoryCost: number;
  iterations: number;
  parallelism: number;
}

export const KDF_LIMITS = {
  memoryCost: { min: 19 * 1024, max: 1024 * 1024 },
  iterations: { min: 2, max: 100 },
  parallelism: { min: 1, max: 1 },
} as const;

/** Returned by /prelogin for unknown emails so they look like real accounts. */
export const DEFAULT_KDF_PARAMS: Readonly<KdfParams> = Object.freeze({
  memoryCost: 64 * 1024,
  iterations: 3,
  parallelism: 1,
});
