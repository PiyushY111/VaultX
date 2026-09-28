import type { KeyValueStore } from './storage';

/**
 * The highest revision this browser has seen for each item, kept in
 * chrome.storage.local per account, so a server that serves an older copy of
 * an item is caught (the web vault keeps the same ledger in localStorage).
 * It holds only item ids and revision numbers.
 */

export interface ItemVersion {
  id: string;
  revision: number;
}

/** The user's decision to trust a vault that had no usable manifest (same as the web vault's). */
export interface AcceptedBaseline {
  version: number;
  itemCount: number;
  reason: 'none' | 'missing' | 'tampered';
  acceptedAt: string;
}

export interface RevisionLedger {
  findRollbacks(items: readonly ItemVersion[]): Promise<Set<string>>;
  record(items: readonly ItemVersion[]): Promise<void>;
  /** The newest vault manifest version this browser has seen (0 if none). */
  manifestVersion(): Promise<number>;
  recordManifest(version: number): Promise<void>;
  /** Records an accepted baseline; sets the seen manifest version to it, even if lower. */
  acceptBaseline(baseline: AcceptedBaseline): Promise<void>;
  baseline(): Promise<AcceptedBaseline | null>;
}

// Stored alongside the item ids, which are UUIDs, so it can't collide.
const MANIFEST_KEY = '#manifest';

export function createRevisionLedger(store: KeyValueStore, email: string): RevisionLedger {
  const key = `revisions:${email}`;
  const load = async () => (await store.get<Record<string, number>>(key)) ?? {};
  return {
    async findRollbacks(items) {
      const seen = await load();
      return new Set(
        items
          .filter((item) => item.id !== MANIFEST_KEY && item.revision < (seen[item.id] ?? 0))
          .map((item) => item.id),
      );
    },
    async record(items) {
      const seen = await load();
      for (const { id, revision } of items) seen[id] = Math.max(seen[id] ?? 0, revision);
      await store.set(key, seen);
    },
    async manifestVersion() {
      return (await load())[MANIFEST_KEY] ?? 0;
    },
    async recordManifest(version) {
      const seen = await load();
      seen[MANIFEST_KEY] = Math.max(seen[MANIFEST_KEY] ?? 0, version);
      await store.set(key, seen);
    },
    async acceptBaseline(baseline) {
      const seen = await load();
      seen[MANIFEST_KEY] = baseline.version;
      await store.set(key, seen);
      await store.set(`baseline:${email}`, baseline);
    },
    async baseline() {
      return (await store.get<AcceptedBaseline>(`baseline:${email}`)) ?? null;
    },
  };
}
