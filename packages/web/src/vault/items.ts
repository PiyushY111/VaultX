import { LEGACY_ITEM_REVISION, decryptItem, encryptItem } from '@password-manager/crypto';
import type { ItemResponse, ItemRevisionPayload } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';
import type { RevisionLedger } from './revisionLedger';

export interface VaultItemData {
  site: string;
  username: string;
  password: string;
  notes: string;
}

export interface VaultItem extends VaultItemData {
  id: string;
  /** The revision this copy was saved as; the next save must be revision + 1. */
  revision: number;
  createdAt: string;
  updatedAt: string;
}

/** Version tag inside the encrypted JSON, so the item format can evolve. */
const ITEM_FORMAT_VERSION = 1;

export const emptyItem = (): VaultItemData => ({ site: '', username: '', password: '', notes: '' });

export function serializeItem(data: VaultItemData): string {
  const { site, username, password, notes } = data;
  return JSON.stringify({ v: ITEM_FORMAT_VERSION, site, username, password, notes });
}

export function parseItem(json: string): VaultItemData {
  const value: unknown = JSON.parse(json);
  if (typeof value !== 'object' || value === null) throw new Error('Item is not an object');
  const record = value as Record<string, unknown>;
  if (record.v !== ITEM_FORMAT_VERSION)
    throw new Error(`Unsupported item version: ${String(record.v)}`);
  const field = (name: keyof VaultItemData): string => {
    const fieldValue = record[name];
    if (typeof fieldValue !== 'string') throw new Error(`Item field "${name}" is not a string`);
    return fieldValue;
  };
  return {
    site: field('site'),
    username: field('username'),
    password: field('password'),
    notes: field('notes'),
  };
}

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

/** Case-insensitive search over decrypted, in-memory items only. Passwords are never matched. */
export function filterItems(items: VaultItem[], query: string): VaultItem[] {
  const needle = query.trim().toLowerCase();
  const sorted = [...items].sort((a, b) =>
    a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
  );
  if (!needle) return sorted;
  return sorted.filter((item) =>
    [item.site, item.username, item.notes].some((value) => value.toLowerCase().includes(needle)),
  );
}
