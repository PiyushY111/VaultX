/** Length in bytes of every symmetric key in this module. */
export const KEY_BYTES = 32;

/** Argon2id salt length (libsodium's crypto_pwhash_SALTBYTES). */
export const SALT_BYTES = 16;

/** XChaCha20-Poly1305 nonce length. */
export const NONCE_BYTES = 24;

/** Poly1305 authentication tag length appended to every ciphertext. */
export const TAG_BYTES = 16;

// Domain-separation labels. Changing any of these changes every derived key or
// ciphertext and breaks existing vaults — bump the version instead.
export const HKDF_INFO_STRETCHED_MASTER_KEY = 'password-manager:v1:stretched-master-key';
export const HKDF_INFO_AUTH_HASH = 'password-manager:v1:auth-hash';
export const AAD_VAULT_KEY = 'password-manager:v1:vault-key';
/** Items saved before ciphertexts were bound to their ID and revision (stored as revision 0). */
export const AAD_ITEM_LEGACY = 'password-manager:v1:item';
/** Prefix of an item's AAD; the item ID and revision are appended (see aead.ts). */
export const AAD_ITEM = 'password-manager:v2:item';
/** Prefix of the vault manifest's AAD; the manifest version is appended (see manifest.ts). */
export const AAD_MANIFEST = 'password-manager:v1:manifest';
