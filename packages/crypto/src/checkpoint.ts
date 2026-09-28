import { HKDF_INFO_CHECKPOINT, KEY_BYTES } from './constants.js';
import { CryptoInputError } from './errors.js';
import { hkdfExpand, hkdfExtract } from './keys.js';
import type { VaultManifest } from './manifest.js';
import { getSodium } from './sodium.js';
import { assertBytes } from './validate.js';

/**
 * A vault checkpoint: the manifest's version plus a short fingerprint of its
 * exact contents (every item id and revision), for comparing two devices'
 * view of the vault by eye, over the phone, or against a printed copy.
 *
 * The manifest alone protects each device from a server that hides, adds or
 * rolls back items relative to what that device has seen. What it can't
 * give a brand-new device is whether this is the *latest* vault: a server can
 * serve a whole, self-consistent older copy. A checkpoint copied from another
 * device closes that gap for anyone who compares.
 *
 * The fingerprint is HMAC-SHA256 under a key derived from the vault key
 * (HKDF, info "password-manager:v1:checkpoint"), truncated to 80 bits. Without
 * the vault key it can't be computed, checked or brute-forced, so it tells
 * the server, or whoever reads a printed copy, nothing about the vault's
 * contents. The version number is visible (the server knows it anyway): it
 * says how many times the vault has changed.
 *
 * 80 bits is plenty for this use: forging a match means finding a different
 * manifest with the same fingerprint, which takes the vault key.
 */

export interface VaultCheckpoint {
  version: number;
  /** 16 base32 characters (80 bits). */
  fingerprint: string;
}

export type CheckpointComparison =
  /** Same version and fingerprint: the same vault. */
  | 'match'
  /** Same version, different fingerprint: not the vault the other device saw. */
  | 'mismatch'
  /** This device's vault is older than the checkpoint: a rollback, or this device is behind. */
  | 'rollback'
  /** The checkpoint is older than this device's vault: expected if it has changed since. */
  | 'older-checkpoint';

const FINGERPRINT_BYTES = 10;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

/**
 * The manifest's contents in one unambiguous form: its version and every
 * (id, revision), sorted by id. JSON, so no id can be crafted to collide
 * with another encoding.
 */
function canonical(manifest: VaultManifest): string {
  const entries = Object.entries(manifest.items).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify([manifest.version, entries]);
}

export async function vaultCheckpoint(
  manifest: VaultManifest,
  vaultKey: Uint8Array,
): Promise<VaultCheckpoint> {
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  if (!Number.isSafeInteger(manifest.version) || manifest.version < 1) {
    throw new CryptoInputError('A checkpoint needs a manifest version of 1 or more');
  }
  const sodium = await getSodium();
  const prk = hkdfExtract(sodium, vaultKey);
  const key = hkdfExpand(sodium, prk, HKDF_INFO_CHECKPOINT, KEY_BYTES);
  try {
    const mac = sodium.crypto_auth_hmacsha256(sodium.from_string(canonical(manifest)), key);
    return { version: manifest.version, fingerprint: base32(mac.subarray(0, FINGERPRINT_BYTES)) };
  } finally {
    sodium.memzero(prk);
    sodium.memzero(key);
  }
}

/** "42 · ABCD-EFGH-IJKL-MNOP": easy to read aloud and to type. */
export const formatCheckpoint = ({ version, fingerprint }: VaultCheckpoint): string =>
  `${version} · ${fingerprint.match(/.{1,4}/g)!.join('-')}`;

/**
 * Reads a checkpoint as typed or pasted: the version, then the fingerprint,
 * in any case, with any spaces, dashes, dots or "·" between groups.
 * Throws {@link CryptoInputError} with a message fit to show.
 */
export function parseCheckpoint(input: string): VaultCheckpoint {
  const match = /^\s*v?(\d{1,15})\s*[·.:\-\s]\s*([A-Za-z2-7][A-Za-z2-7\s-]*)$/u.exec(input.trim());
  const fingerprint = match?.[2]!.replace(/[\s-]/g, '').toUpperCase();
  if (!match || fingerprint!.length !== 16) {
    throw new CryptoInputError(
      'That isn’t a checkpoint. It looks like “42 · ABCD-EFGH-IJKL-MNOP”: a version, then 16 letters and digits.',
    );
  }
  const version = Number(match[1]);
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new CryptoInputError('A checkpoint’s version is a whole number, 1 or more.');
  }
  return { version, fingerprint: fingerprint! };
}

/** Compares this device's checkpoint with one copied from elsewhere. */
export async function compareCheckpoints(
  current: VaultCheckpoint,
  claimed: VaultCheckpoint,
): Promise<CheckpointComparison> {
  if (claimed.version > current.version) return 'rollback';
  if (claimed.version < current.version) return 'older-checkpoint';
  const sodium = await getSodium();
  const a = sodium.from_string(current.fingerprint);
  const b = sodium.from_string(claimed.fingerprint);
  return a.length === b.length && sodium.memcmp(a, b) ? 'match' : 'mismatch';
}
