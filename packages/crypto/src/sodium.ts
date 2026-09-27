import sodium from 'libsodium-wrappers-sumo';

/**
 * Returns the initialized libsodium instance.
 *
 * The sumo build is required: the standard `libsodium-wrappers` build omits
 * `crypto_pwhash` (Argon2id) and `crypto_auth_hmacsha256` (needed for HKDF).
 */
export async function getSodium(): Promise<typeof sodium> {
  await sodium.ready;
  return sodium;
}
