import { decryptItem, encryptItem } from '@password-manager/crypto';
import { parseItem, serializeItem, type VaultItemData } from '@password-manager/item-format';
import { fromBase64, toBase64 } from '../shared/base64';
import type { ItemResponse, ItemRevisionPayload } from './api';
import type { RevisionLedger } from './revisions';

// The item format itself lives in @password-manager/item-format, shared with
// the web vault; re-exported here so the rest of the extension imports it
// from one place.
export {
  MATCH_MODES,
  ITEM_TYPES,
  MAX_PASSWORD_HISTORY,
  TRASH_RETENTION_DAYS,
  isLogin,
  isTrashed,
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
