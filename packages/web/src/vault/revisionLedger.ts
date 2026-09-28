/**
 * Remembers the highest revision this browser has seen for each item, so a
 * server that serves an older copy of an item is caught.
 *
 * Revisions are bound into each ciphertext, so the server can't relabel an
 * old ciphertext as a newer revision; what it could still do is serve the old
 * ciphertext at its old revision. This ledger closes that for every item this
 * browser has already seen. It can't help a browser that has never seen the
 * vault, and it can't tell an item the server withholds from one deleted on
 * another device (see THREAT_MODEL.md).
 *
 * It holds only item ids and revision numbers, never item contents, so
 * localStorage is fine for it.
 */

export interface ItemVersion {
  id: string;
  revision: number;
}

export interface RevisionLedger {
  /** Ids of items older than a revision this browser has already seen. */
  findRollbacks(items: readonly ItemVersion[]): Set<string>;
  record(items: readonly ItemVersion[]): void;
  /** Deleted items stay recorded, so the server can't bring them back. */
  markDeleted(id: string): void;
  /** The newest vault manifest version this browser has seen (0 if none). */
  manifestVersion(): number;
  recordManifest(version: number): void;
}

const STORAGE_PREFIX = 'password-manager.revisions:';
const DELETED = Number.MAX_SAFE_INTEGER;
// Stored alongside the item ids, which are UUIDs, so it can't collide.
const MANIFEST_KEY = '#manifest';

export const revisionStorageKey = (email: string) => `${STORAGE_PREFIX}${email}`;

function defaultStorage(): Storage | null {
  try {
    return localStorage;
  } catch {
    return null;
  }
}

export function createRevisionLedger(
  email: string,
  storage: Storage | null = defaultStorage(),
): RevisionLedger {
  const key = revisionStorageKey(email);
  // Kept in memory too, so detection still works for this page's lifetime if
  // storage is unavailable (private mode, quota).
  let known: Record<string, number> = {};

  function load(): Record<string, number> {
    try {
      const parsed: unknown = JSON.parse(storage?.getItem(key) ?? '{}');
      if (typeof parsed === 'object' && parsed !== null) {
        for (const [id, revision] of Object.entries(parsed)) {
          if (Number.isSafeInteger(revision)) known[id] = Math.max(known[id] ?? 0, revision);
        }
      }
    } catch {
      // Corrupt or unavailable: fall back to what this page has seen.
    }
    return known;
  }

  function save(): void {
    try {
      storage?.setItem(key, JSON.stringify(known));
    } catch {
      // Keep the in-memory copy.
    }
  }

  return {
    findRollbacks(items) {
      const seen = load();
      return new Set(
        items
          .filter((item) => item.id !== MANIFEST_KEY && item.revision < (seen[item.id] ?? 0))
          .map((item) => item.id),
      );
    },
    record(items) {
      known = load();
      for (const { id, revision } of items) known[id] = Math.max(known[id] ?? 0, revision);
      save();
    },
    markDeleted(id) {
      known = load();
      known[id] = DELETED;
      save();
    },
    manifestVersion() {
      return load()[MANIFEST_KEY] ?? 0;
    },
    recordManifest(version) {
      known = load();
      known[MANIFEST_KEY] = Math.max(known[MANIFEST_KEY] ?? 0, version);
      save();
    },
  };
}
