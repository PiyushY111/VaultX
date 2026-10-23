import { LEGACY_ITEM_REVISION, decryptItem, encryptItem } from '@password-manager/crypto';
import {
  isTrashed,
  parseItem,
  serializeItem,
  type ItemType,
  type VaultItemData,
} from '@password-manager/item-format';
import type { ItemResponse, ItemRevisionPayload } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';
import { isInFolder } from './folders';
import type { RevisionLedger } from './revisionLedger';

// The item format itself lives in @password-manager/item-format, shared with
// the extension; re-exported here so the rest of the web vault imports it
// from one place.
export {
  MATCH_MODES,
  CARD_FIELDS,
  IDENTITY_FIELDS,
  ITEM_TYPES,
  MAX_FOLDER_DEPTH,
  MAX_FOLDER_SEGMENT,
  MAX_PASSWORD_HISTORY,
  TRASH_RETENTION_DAYS,
  isLogin,
  isTrashed,
  normalizeFolder,
  normalizeTags,
  parseItem,
  serializeItem,
  trashExpired,
  withPasswordHistory,
  type ItemType,
  type MatchMode,
  type PasswordHistoryEntry,
  type VaultItemData,
} from '@password-manager/item-format';

export interface VaultItem extends VaultItemData {
  id: string;
  /** The revision this copy was saved as; the next save must be revision + 1. */
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export const emptyItem = (type: ItemType = 'login'): VaultItemData => ({
  ...(type !== 'login' && { type }),
  site: '',
  username: '',
  password: '',
  notes: '',
});

/** When the current password was set: the last replacement, else the item's creation. */
export const passwordChangedAt = (item: VaultItem): string =>
  item.history?.at(-1)?.changedAt ?? item.createdAt;

/**
 * Encrypts one revision of an item, bound to its id and revision number. A
 * fresh random nonce is generated on every call.
 */
export async function encryptVaultItem(
  data: VaultItemData,
  vaultKey: Uint8Array,
  id: string,
  revision: number,
): Promise<ItemRevisionPayload> {
  const { ciphertext, nonce } = await encryptItem(serializeItem(data), vaultKey, {
    itemId: id,
    revision,
  });
  return { id, revision, encrypted_data: toBase64(ciphertext), nonce: toBase64(nonce) };
}

/** A brand-new item: the client picks its id, and it starts at revision 1. */
export const encryptNewItem = (data: VaultItemData, vaultKey: Uint8Array) =>
  encryptVaultItem(data, vaultKey, crypto.randomUUID(), 1);

/** The next revision of an existing item. */
export const encryptNextRevision = (
  item: Pick<VaultItem, 'id' | 'revision'>,
  data: VaultItemData,
  vaultKey: Uint8Array,
) => encryptVaultItem(data, vaultKey, item.id, item.revision + 1);

export function toVaultItem(response: ItemResponse, data: VaultItemData): VaultItem {
  return {
    ...data,
    id: response.id,
    revision: response.revision,
    createdAt: response.created_at,
    updatedAt: response.updated_at,
  };
}

/** Items saved before ciphertexts were bound to their id and revision. */
export const isLegacyItem = (item: Pick<VaultItem, 'revision'>) =>
  item.revision === LEGACY_ITEM_REVISION;

export interface DecryptedVault {
  items: VaultItem[];
  /** Failed authentication: tampered, corrupted, or moved to another id or revision. */
  failedIds: string[];
  /** Older than a revision this browser has already seen: rolled back by the server. */
  rolledBackIds: string[];
}

/**
 * Decrypts every item. Items that fail authentication, or that the ledger
 * shows are older than a copy this browser has seen, are reported by id
 * instead of aborting the whole vault, and left out of `items`.
 */
export async function decryptVaultItems(
  responses: ItemResponse[],
  vaultKey: Uint8Array,
  ledger?: RevisionLedger,
): Promise<DecryptedVault> {
  const items: VaultItem[] = [];
  const failedIds: string[] = [];
  const rolledBack = ledger?.findRollbacks(responses) ?? new Set<string>();
  for (const response of responses) {
    if (rolledBack.has(response.id)) continue;
    try {
      const json = await decryptItem(
        fromBase64(response.encrypted_data),
        fromBase64(response.nonce),
        vaultKey,
        { itemId: response.id, revision: response.revision },
      );
      items.push(toVaultItem(response, parseItem(json)));
    } catch {
      failedIds.push(response.id);
    }
  }
  ledger?.record(items);
  return { items, failedIds, rolledBackIds: [...rolledBack] };
}

export interface ItemFilter {
  tag?: string | null;
  favoritesOnly?: boolean;
  /** Search the trash instead of the vault (each leaves the other out). */
  trash?: boolean;
  /** A folder (with its subfolders), '' for items in no folder, or null for all. */
  folder?: string | null;
}

/**
 * Case-insensitive search over decrypted, in-memory items only. Matches the
 * title/site, username, notes, tags, folder and card/identity details; never
 * passwords or card security codes. Favorites come first.
 */
export function filterItems(
  items: VaultItem[],
  query: string,
  { tag = null, favoritesOnly = false, trash = false, folder = null }: ItemFilter = {},
): VaultItem[] {
  const needle = query.trim().toLowerCase();
  const sorted = [...items].sort(
    (a, b) =>
      Number(Boolean(b.favorite)) - Number(Boolean(a.favorite)) ||
      a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
  );
  return sorted.filter((item) => {
    if (isTrashed(item) !== trash) return false;
    if (folder === '' ? item.folder : folder !== null && !isInFolder(item, folder)) return false;
    if (favoritesOnly && !item.favorite) return false;
    if (tag && !item.tags?.some((t) => t.toLowerCase() === tag.toLowerCase())) return false;
    if (!needle) return true;
    const haystack = [
      item.site,
      item.username,
      item.notes,
      ...(item.tags ?? []),
      item.folder ?? '',
      ...Object.entries(item.fields ?? {})
        .filter(([key]) => key !== 'cvv')
        .map(([, value]) => value),
    ];
    return haystack.some((value) => value.toLowerCase().includes(needle));
  });
}
