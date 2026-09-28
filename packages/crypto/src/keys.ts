import { HKDF_INFO_AUTH_HASH, HKDF_INFO_STRETCHED_MASTER_KEY, KEY_BYTES } from './constants.js';
import { getSodium } from './sodium.js';
import { assertBytes } from './validate.js';

type Sodium = Awaited<ReturnType<typeof getSodium>>;

export interface DerivedKeys {
  /** Encrypts/decrypts the vault key. Never leaves the client. */
  stretchedMasterKey: Uint8Array;
  /**
   * Sent to the server for login verification. Derived with a different HKDF
   * `info` label, so it reveals nothing about `stretchedMasterKey` and cannot
   * decrypt anything. The server should still hash it before storing it.
   */
  authHash: Uint8Array;
}

const HASH_BYTES = 32;

/** HKDF-Extract (RFC 5869) with HMAC-SHA256 and an empty salt. */
export function hkdfExtract(sodium: Sodium, ikm: Uint8Array): Uint8Array {
  // An absent salt is defined as HashLen zero bytes, which is also what an
  // empty HMAC key pads to.
  const salt = new Uint8Array(HASH_BYTES);
  return sodium.crypto_auth_hmacsha256(ikm, salt);
}

/** HKDF-Expand (RFC 5869) with HMAC-SHA256. */
export function hkdfExpand(
  sodium: Sodium,
  prk: Uint8Array,
  info: string,
  length: number,
): Uint8Array {
  const infoBytes = sodium.from_string(info);
  const out = new Uint8Array(length);
  let previous: Uint8Array = new Uint8Array(0);
  for (let i = 1, offset = 0; offset < length; i++) {
    const input = new Uint8Array(previous.length + infoBytes.length + 1);
    input.set(previous, 0);
    input.set(infoBytes, previous.length);
    input[input.length - 1] = i;
    const block = sodium.crypto_auth_hmacsha256(input, prk);
    out.set(block.subarray(0, Math.min(block.length, length - offset)), offset);
    offset += block.length;
    sodium.memzero(previous);
    sodium.memzero(input);
    previous = block;
  }
  sodium.memzero(previous);
  return out;
}

/**
 * Splits the master key into two independent keys via HKDF-SHA256, using
 * distinct `info` labels for domain separation.
 */
export async function deriveKeys(masterKey: Uint8Array): Promise<DerivedKeys> {
  assertBytes(masterKey, KEY_BYTES, 'masterKey');
  const sodium = await getSodium();
  const prk = hkdfExtract(sodium, masterKey);
  try {
    return {
      stretchedMasterKey: hkdfExpand(sodium, prk, HKDF_INFO_STRETCHED_MASTER_KEY, KEY_BYTES),
      authHash: hkdfExpand(sodium, prk, HKDF_INFO_AUTH_HASH, KEY_BYTES),
    };
  } finally {
    sodium.memzero(prk);
  }
}
