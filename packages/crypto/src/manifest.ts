import { AAD_MANIFEST, KEY_BYTES, NONCE_BYTES, TAG_BYTES } from './constants.js';
import { CryptoInputError, DecryptionError } from './errors.js';
import { getSodium } from './sodium.js';
import { assertBytes } from './validate.js';
import type { EncryptedPayload } from './aead.js';

/**
 * The vault manifest: an encrypted list of every item id and its current
 * revision, kept on the server next to the items and replaced (at the next
 * version) in the same transaction as every item write.
 *
 * Only a holder of the vault key can write one, so a client that checks the
 * items it's served against the manifest can tell when the server hides an
 * item, adds one, serves an older revision of one, or brings a deleted one
 * back — even on a device that has never seen the vault before. What the
 * manifest can't prove to a new device is that it's the *latest* manifest;
 * its timestamp is shown so a person can judge.
 */
export interface VaultManifest {
  /** Starts at 1 and goes up by one with every change to the vault. */
  version: number;
  /** Item id → revision. */
  items: Record<string, number>;
  /** When and from which client the vault last changed (ISO 8601). */
  updatedAt: string;
  updatedBy: string;
}

const MANIFEST_FORMAT = 1;

function manifestAad(version: number): string {
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new CryptoInputError('manifest version must be a positive integer');
  }
  return `${AAD_MANIFEST}\0${version}`;
}

function validate(manifest: unknown): VaultManifest {
  if (typeof manifest !== 'object' || manifest === null) {
    throw new CryptoInputError('manifest must be an object');
  }
  const { version, items, updatedAt, updatedBy } = manifest as Record<string, unknown>;
  manifestAad(version as number);
  if (typeof items !== 'object' || items === null || Array.isArray(items)) {
    throw new CryptoInputError('manifest.items must be an object');
  }
  for (const revision of Object.values(items)) {
    if (!Number.isSafeInteger(revision) || (revision as number) < 0) {
      throw new CryptoInputError('manifest revisions must be non-negative integers');
    }
  }
  if (typeof updatedAt !== 'string' || typeof updatedBy !== 'string') {
    throw new CryptoInputError('manifest.updatedAt and updatedBy must be strings');
  }
  return {
    version: version as number,
    items: items as Record<string, number>,
    updatedAt,
    updatedBy,
  };
}

/** Encrypts a manifest under the vault key, bound to its version. */
export async function encryptManifest(
  manifest: VaultManifest,
  vaultKey: Uint8Array,
): Promise<EncryptedPayload> {
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  const { version, items, updatedAt, updatedBy } = validate(manifest);
  const sodium = await getSodium();
  const plaintext = sodium.from_string(
    JSON.stringify({
      v: MANIFEST_FORMAT,
      version,
      items,
      updated_at: updatedAt,
      updated_by: updatedBy,
    }),
  );
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    sodium.from_string(manifestAad(version)),
    null,
    nonce,
    vaultKey,
  );
  return { ciphertext, nonce };
}

/**
 * Decrypts the manifest the server says is at `version`. Throws
 * {@link DecryptionError} if it was tampered with, written under another
 * key, or is really a different version.
 */
export async function decryptManifest(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  vaultKey: Uint8Array,
  version: number,
): Promise<VaultManifest> {
  assertBytes(vaultKey, KEY_BYTES, 'vaultKey');
  assertBytes(nonce, NONCE_BYTES, 'nonce');
  const aad = manifestAad(version);
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < TAG_BYTES) {
    throw new DecryptionError();
  }
  const sodium = await getSodium();
  let plaintext: Uint8Array;
  try {
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      sodium.from_string(aad),
      nonce,
      vaultKey,
    );
  } catch {
    throw new DecryptionError();
  }
  const record = JSON.parse(sodium.to_string(plaintext)) as Record<string, unknown>;
  if (record.v !== MANIFEST_FORMAT || record.version !== version) throw new DecryptionError();
  return validate({
    version: record.version,
    items: record.items,
    updatedAt: record.updated_at,
    updatedBy: record.updated_by,
  });
}

export interface ItemVersion {
  id: string;
  revision: number;
}

/** How the items a server returned differ from the manifest. Every list is empty for an honest server. */
export interface ManifestCheck {
  /** Listed in the manifest but not returned: hidden (or deleted without updating the manifest). */
  missing: string[];
  /** Returned but not listed: added by someone without the vault key, or brought back after deletion. */
  unexpected: string[];
  /** Returned at a different revision than the manifest lists (e.g. rolled back). */
  mismatched: string[];
}

export function checkAgainstManifest(
  manifest: VaultManifest,
  items: readonly ItemVersion[],
): ManifestCheck {
  const served = new Map(items.map((item) => [item.id, item.revision]));
  const listed = Object.entries(manifest.items);
  return {
    missing: listed.filter(([id]) => !served.has(id)).map(([id]) => id),
    unexpected: items.filter((item) => !(item.id in manifest.items)).map((item) => item.id),
    mismatched: items
      .filter((item) => item.id in manifest.items && manifest.items[item.id] !== item.revision)
      .map((item) => item.id),
  };
}

/** The manifest after a change, at the next version. `current` is null for a vault that has none yet. */
export function nextManifest(
  current: VaultManifest | null,
  change: { set?: readonly ItemVersion[]; remove?: readonly string[]; replaceAll?: boolean },
  updatedBy: string,
  now: Date = new Date(),
): VaultManifest {
  const items: Record<string, number> = change.replaceAll ? {} : { ...(current?.items ?? {}) };
  for (const id of change.remove ?? []) delete items[id];
  for (const { id, revision } of change.set ?? []) items[id] = revision;
  return {
    version: (current?.version ?? 0) + 1,
    items,
    updatedAt: now.toISOString(),
    updatedBy,
  };
}
