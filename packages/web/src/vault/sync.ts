import {
  DecryptionError,
  checkAgainstManifest,
  decryptManifest,
  encryptManifest,
  nextManifest,
  type ItemVersion,
  type VaultManifest,
} from '@password-manager/crypto';
import { ApiError, api, type ManifestPayload } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';
import {
  decryptVaultItems,
  encryptNewItem,
  encryptNextRevision,
  isLegacyItem,
  toVaultItem,
  type VaultItem,
  type VaultItemData,
} from './items';
import type { AcceptedBaseline, RevisionLedger } from './revisionLedger';
import type { VaultSession } from './session';

/**
 * Loads and writes the vault, keeping it consistent with its manifest: the
 * encrypted list of every item id and revision that each write moves to the
 * next version (see @password-manager/crypto's manifest.ts).
 *
 * On load, anything that doesn't match is hidden and reported: items the
 * manifest doesn't list, items at another revision, items it lists that the
 * server didn't return, and a manifest older than one this browser has seen.
 */

export const CLIENT_NAME = 'web';

export interface VaultWarnings {
  /** Failed authentication: tampered, corrupted, or moved to another id or revision. */
  failedIds: string[];
  /** Older than a revision this browser has seen, or not the revision the manifest lists. */
  rolledBackIds: string[];
  /** Listed in the manifest, but the server didn't return them. */
  missingIds: string[];
  /** Returned by the server but not in the manifest (e.g. a deleted item brought back). */
  unexpectedIds: string[];
  /** Something is wrong with the manifest itself. */
  manifest: 'tampered' | 'stale' | 'missing' | null;
}

/**
 * The vault has no manifest this browser can trust, so there's nothing to
 * check the server's items against. Rather than silently adopting whatever
 * the server sent as the truth (trust on first use without asking), the
 * vault loads read-only until the user accepts it as the baseline.
 */
export interface PendingBaseline {
  /**
   * - `none`: the vault never had a manifest (created before manifests existed).
   * - `missing`: this browser has seen a manifest before, and the server no longer has one.
   * - `tampered`: the server's manifest doesn't decrypt under the vault key.
   */
  reason: AcceptedBaseline['reason'];
  /** Items that decrypted and would become the baseline. */
  itemCount: number;
  /** The server's (unverified) timestamps for those items. */
  oldestUpdate: string | null;
  newestUpdate: string | null;
  /** The manifest version this browser saw before, if any (0 if none). */
  previouslySeenVersion: number;
}

export interface LoadedVault {
  items: VaultItem[];
  warnings: VaultWarnings;
  /** When the vault last changed and from which client, per the manifest. */
  lastChanged: { at: string; by: string } | null;
  /** Set when the vault needs the user to accept a baseline before it can be changed. */
  baseline: PendingBaseline | null;
}

/** A write was attempted before the user accepted the vault's baseline. */
export class BaselineRequiredError extends Error {
  constructor() {
    super('Confirm this vault as your trusted starting point before changing it.');
    this.name = 'BaselineRequiredError';
  }
}

/** The vault changed elsewhere since it was loaded (the manifest moved on). */
export class VaultChangedError extends Error {
  constructor(options?: ErrorOptions) {
    super('Your vault was changed elsewhere since it was loaded.', options);
    this.name = 'VaultChangedError';
  }
}

export const countWarnings = (w: VaultWarnings) =>
  w.failedIds.length +
  w.rolledBackIds.length +
  w.missingIds.length +
  w.unexpectedIds.length +
  (w.manifest ? 1 : 0);

async function encryptManifestPayload(
  manifest: VaultManifest,
  vaultKey: Uint8Array,
): Promise<ManifestPayload> {
  const { ciphertext, nonce } = await encryptManifest(manifest, vaultKey);
  return {
    version: manifest.version,
    encrypted_data: toBase64(ciphertext),
    nonce: toBase64(nonce),
  };
}

/** Re-throws a manifest conflict (409 with manifest_version) as {@link VaultChangedError}. */
function rethrow(error: unknown): never {
  if (error instanceof ApiError && error.status === 409 && 'manifest_version' in error.details) {
    throw new VaultChangedError({ cause: error });
  }
  throw error;
}

export class VaultSync {
  /** The manifest the next write builds on. Null only before the first load. */
  private manifest: VaultManifest | null = null;
  /** Set while the vault waits for the user to accept (or decline) a baseline. */
  private pendingBaseline: PendingBaseline | null = null;

  constructor(
    private readonly session: VaultSession,
    private readonly ledger: RevisionLedger,
  ) {}

  async load(): Promise<LoadedVault> {
    const { items: responses, manifest: payload } = await api.listItems(this.session.token);
    const decrypted = await decryptVaultItems(responses, this.session.vaultKey, this.ledger);
    const warnings: VaultWarnings = {
      failedIds: decrypted.failedIds,
      rolledBackIds: decrypted.rolledBackIds,
      missingIds: [],
      unexpectedIds: [],
      manifest: null,
    };

    let manifest: VaultManifest | null = null;
    if (payload) {
      try {
        manifest = await decryptManifest(
          fromBase64(payload.encrypted_data),
          fromBase64(payload.nonce),
          this.session.vaultKey,
          payload.version,
        );
      } catch (error) {
        if (!(error instanceof DecryptionError)) throw error;
        warnings.manifest = 'tampered';
      }
    }
    const seenVersion = this.ledger.manifestVersion();
    if (manifest && manifest.version < seenVersion) warnings.manifest = 'stale';
    if (!payload && seenVersion > 0) warnings.manifest = 'missing';

    let items = decrypted.items;
    if (manifest) {
      const check = checkAgainstManifest(manifest, responses);
      warnings.missingIds = check.missing;
      warnings.unexpectedIds = check.unexpected;
      const hidden = new Set([...check.unexpected, ...check.mismatched]);
      warnings.rolledBackIds = [...new Set([...warnings.rolledBackIds, ...check.mismatched])];
      items = items.filter((item) => !hidden.has(item.id));
      this.manifest = manifest;
      this.ledger.recordManifest(manifest.version);
      this.pendingBaseline = null;
    } else {
      // No usable manifest. What this browser could verify becomes the
      // candidate baseline, at the version after the server's; nothing is
      // written until the user accepts it (acceptBaseline).
      this.manifest = {
        version: payload?.version ?? 0,
        items: Object.fromEntries(items.map((item) => [item.id, item.revision])),
        updatedAt: '',
        updatedBy: '',
      };
      const dates = items.map((item) => item.updatedAt).sort();
      this.pendingBaseline = {
        reason: payload ? 'tampered' : seenVersion > 0 ? 'missing' : 'none',
        itemCount: items.length,
        oldestUpdate: dates[0] ?? null,
        newestUpdate: dates.at(-1) ?? null,
        previouslySeenVersion: seenVersion,
      };
    }

    return {
      // Legacy items are re-saved (a write) only once there's a trusted manifest.
      items: this.pendingBaseline ? items : await this.upgradeLegacyItems(items),
      warnings,
      lastChanged: manifest?.updatedAt ? { at: manifest.updatedAt, by: manifest.updatedBy } : null,
      baseline: this.pendingBaseline,
    };
  }

  /** The baseline waiting for the user's decision, if any. */
  baseline(): PendingBaseline | null {
    return this.pendingBaseline;
  }

  /**
   * The user accepted the vault as loaded: writes its first trusted manifest
   * (at the version after the server's) and records the decision in the
   * revision ledger. Returns the items, with any legacy ones re-saved.
   */
  async acceptBaseline(items: VaultItem[]): Promise<VaultItem[]> {
    const pending = this.pendingBaseline;
    if (!pending || !this.manifest) throw new Error('There is no baseline to accept.');
    // The candidate built on load: exactly the items the user was shown.
    const manifest = nextManifest(this.manifest, {}, CLIENT_NAME);
    try {
      await api.putManifest(
        this.session.token,
        await encryptManifestPayload(manifest, this.session.vaultKey),
      );
    } catch (error) {
      rethrow(error);
    }
    this.pendingBaseline = null;
    this.manifest = manifest;
    this.ledger.acceptBaseline({
      version: manifest.version,
      itemCount: pending.itemCount,
      reason: pending.reason,
      acceptedAt: new Date().toISOString(),
    });
    return this.upgradeLegacyItems(items);
  }

  /** The current manifest's view of the vault, for a password change (which writes a new one). */
  currentManifest(): VaultManifest {
    if (!this.manifest) throw new Error('Load the vault first');
    if (this.pendingBaseline) throw new BaselineRequiredError();
    return this.manifest;
  }

  /** The manifest this browser trusts, for the checkpoint; null until there is one. */
  trustedManifest(): VaultManifest | null {
    return this.pendingBaseline || !this.manifest || this.manifest.version < 1
      ? null
      : this.manifest;
  }

  /** After a password change re-encrypted everything, including the manifest. */
  replaceManifest(manifest: VaultManifest): void {
    this.manifest = manifest;
    this.ledger.recordManifest(manifest.version);
  }

  private next(change: { set?: ItemVersion[]; remove?: string[] }): VaultManifest {
    // Every write moves the manifest on, which would quietly make the
    // unconfirmed vault the baseline (currentManifest refuses while one is pending).
    return nextManifest(this.currentManifest(), change, CLIENT_NAME);
  }

  private commit(manifest: VaultManifest, items: ItemVersion[] = []): void {
    this.manifest = manifest;
    this.ledger.record(items);
    this.ledger.recordManifest(manifest.version);
  }

  async create(data: VaultItemData): Promise<VaultItem> {
    const payload = await encryptNewItem(data, this.session.vaultKey);
    const manifest = this.next({ set: [{ id: payload.id, revision: 1 }] });
    try {
      const response = await api.createItem(
        this.session.token,
        payload,
        await encryptManifestPayload(manifest, this.session.vaultKey),
      );
      this.commit(manifest, [response]);
      return toVaultItem(response, data);
    } catch (error) {
      rethrow(error);
    }
  }

  /** Maximum items the server takes in one batch; bigger imports go in several. */
  static readonly BATCH_SIZE = 500;

  /**
   * Adds many items (an import), a batch at a time: each batch is saved with
   * its manifest change in one transaction. Returns what was saved; if a
   * batch fails, the ones before it stay saved and the error says how far it got.
   */
  async createMany(
    data: readonly VaultItemData[],
    onProgress?: (saved: number) => void,
  ): Promise<VaultItem[]> {
    const saved: VaultItem[] = [];
    for (let start = 0; start < data.length; start += VaultSync.BATCH_SIZE) {
      const batch = data.slice(start, start + VaultSync.BATCH_SIZE);
      const payloads = await Promise.all(
        batch.map((item) => encryptNewItem(item, this.session.vaultKey)),
      );
      const manifest = this.next({ set: payloads.map(({ id }) => ({ id, revision: 1 })) });
      try {
        const { items } = await api.createItems(
          this.session.token,
          payloads,
          await encryptManifestPayload(manifest, this.session.vaultKey),
        );
        this.commit(manifest, items);
        saved.push(...items.map((response, i) => toVaultItem(response, batch[i]!)));
        onProgress?.(saved.length);
      } catch (error) {
        if (saved.length === 0) rethrow(error);
        throw new Error(
          `Imported ${saved.length} of ${data.length} logins, then stopped: ${(error as Error).message}`,
          { cause: error },
        );
      }
    }
    return saved;
  }

  async update(item: VaultItem, data: VaultItemData): Promise<VaultItem> {
    const payload = await encryptNextRevision(item, data, this.session.vaultKey);
    const manifest = this.next({ set: [{ id: item.id, revision: payload.revision }] });
    try {
      const response = await api.updateItem(
        this.session.token,
        payload,
        await encryptManifestPayload(manifest, this.session.vaultKey),
      );
      this.commit(manifest, [response]);
      return toVaultItem(response, data);
    } catch (error) {
      rethrow(error);
    }
  }

  async remove(id: string): Promise<void> {
    const manifest = this.next({ remove: [id] });
    try {
      await api.deleteItem(
        this.session.token,
        id,
        await encryptManifestPayload(manifest, this.session.vaultKey),
      );
    } catch (error) {
      rethrow(error);
    }
    this.commit(manifest);
    this.ledger.markDeleted(id);
  }

  /**
   * Re-saves items from before ciphertexts were bound to their id and
   * revision. Best effort: anything that fails is retried on the next load.
   */
  private async upgradeLegacyItems(items: VaultItem[]): Promise<VaultItem[]> {
    const upgraded = [...items];
    for (const [index, item] of items.entries()) {
      if (!isLegacyItem(item)) continue;
      try {
        upgraded[index] = await this.update(item, item);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) throw error;
      }
    }
    return upgraded;
  }
}

export { encryptManifestPayload };
