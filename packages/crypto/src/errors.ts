/** Thrown when a function is called with malformed input (wrong key length, bad params, ...). */
export class CryptoInputError extends Error {
  override name = 'CryptoInputError';
}

/**
 * Thrown when authenticated decryption fails: wrong key, wrong nonce, or
 * tampered ciphertext. Deliberately carries no detail about which.
 */
export class DecryptionError extends Error {
  override name = 'DecryptionError';

  constructor() {
    super('Decryption failed: wrong key or corrupted/tampered data');
  }
}
