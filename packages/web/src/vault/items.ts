import { decryptItem, encryptItem } from '@password-manager/crypto';
import type { EncryptedItemPayload, ItemResponse } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';

export interface VaultItemData {
  site: string;
  username: string;
  password: string;
  notes: string;
}

export interface VaultItem extends VaultItemData {
  id: string;
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

/** Encrypts an item for the server. A fresh random nonce is generated on every call. */
export async function encryptVaultItem(
  data: VaultItemData,
  vaultKey: Uint8Array,
): Promise<EncryptedItemPayload> {
  const { ciphertext, nonce } = await encryptItem(serializeItem(data), vaultKey);
  return { encrypted_data: toBase64(ciphertext), nonce: toBase64(nonce) };
}

export function toVaultItem(response: ItemResponse, data: VaultItemData): VaultItem {
  return {
    ...data,
    id: response.id,
    createdAt: response.created_at,
    updatedAt: response.updated_at,
  };
}

/**
 * Decrypts every item. Items that fail authentication (tampered or corrupted
 * on the server) are reported by id instead of aborting the whole vault.
 */
export async function decryptVaultItems(
  responses: ItemResponse[],
  vaultKey: Uint8Array,
): Promise<{ items: VaultItem[]; failedIds: string[] }> {
  const items: VaultItem[] = [];
  const failedIds: string[] = [];
  for (const response of responses) {
    try {
      const json = await decryptItem(
        fromBase64(response.encrypted_data),
        fromBase64(response.nonce),
        vaultKey,
      );
      items.push(toVaultItem(response, parseItem(json)));
    } catch {
      failedIds.push(response.id);
    }
  }
  return { items, failedIds };
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
