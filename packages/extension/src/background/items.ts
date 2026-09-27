import { decryptItem, encryptItem } from '@password-manager/crypto';
import { fromBase64, toBase64 } from '../shared/base64';
import type { ItemResponse, ItemRevisionPayload } from './api';
import type { RevisionLedger } from './revisions';

// The encrypted item format is shared with packages/web (test/interop.test.ts
// checks the two stay compatible).

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
}

const ITEM_FORMAT_VERSION = 1;

export function serializeItem({ site, username, password, notes }: VaultItemData): string {
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

/** Encrypts one revision of an item, bound to its id and revision number. */
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

/**
 * Decrypts items, skipping (and counting) any that fail authentication or
 * that the ledger shows are older than a revision already seen.
 */
export async function decryptVaultItems(
  responses: ItemResponse[],
  vaultKey: Uint8Array,
  ledger?: RevisionLedger,
): Promise<{ items: VaultItem[]; failed: number; rolledBack: number }> {
  const items: VaultItem[] = [];
  let failed = 0;
  const rolledBack = (await ledger?.findRollbacks(responses)) ?? new Set<string>();
  for (const response of responses) {
    if (rolledBack.has(response.id)) continue;
    try {
      const json = await decryptItem(
        fromBase64(response.encrypted_data),
        fromBase64(response.nonce),
        vaultKey,
        { itemId: response.id, revision: response.revision },
      );
      items.push({ id: response.id, revision: response.revision, ...parseItem(json) });
    } catch {
      failed++;
    }
  }
  await ledger?.record(items);
  return { items, failed, rolledBack: rolledBack.size };
}
