import { decryptItem, encryptItem } from '@password-manager/crypto';
import { fromBase64, toBase64 } from '../shared/base64';
import type { ItemResponse, ItemRevisionPayload } from './api';
import type { RevisionLedger } from './revisions';

// The encrypted item format is shared with packages/web (test/interop.test.ts
// checks the two stay compatible).

export type ItemType = 'login' | 'note' | 'card' | 'identity';
export const ITEM_TYPES: readonly ItemType[] = ['login', 'note', 'card', 'identity'];

export interface PasswordHistoryEntry {
  password: string;
  /** When this password was replaced (ISO 8601). */
  changedAt: string;
}

export interface VaultItemData {
  /** `login` when left out. */
  type?: ItemType;
  /** The site for a login; the title for other kinds of item. */
  site: string;
  username: string;
  password: string;
  notes: string;
  /**
   * The site's two-factor setup key or otpauth:// link, if saved. Optional,
   * and left out of the JSON when empty, so items without one encrypt exactly
   * as before.
   */
  totp?: string;
  tags?: string[];
  favorite?: boolean;
  /** Card and identity details, keyed as in the web vault's CARD_FIELDS and IDENTITY_FIELDS. */
  fields?: Record<string, string>;
  /** Earlier passwords, oldest first. Kept to {@link MAX_PASSWORD_HISTORY}. */
  history?: PasswordHistoryEntry[];
}

const ITEM_FORMAT_VERSION = 1;

export const MAX_PASSWORD_HISTORY = 10;

export const isLogin = (item: Pick<VaultItemData, 'type'>): boolean =>
  !item.type || item.type === 'login';

/** "work, Personal ,work" → ["work", "Personal"]. */
export function normalizeTags(input: string | readonly string[]): string[] {
  const raw = typeof input === 'string' ? input.split(',') : input;
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const tag of raw.map((t) => t.trim()).filter(Boolean)) {
    if (seen.has(tag.toLowerCase())) continue;
    seen.add(tag.toLowerCase());
    tags.push(tag);
  }
  return tags;
}

export function serializeItem(data: VaultItemData): string {
  const { type, site, username, password, notes, totp, tags, favorite, fields, history } = data;
  const kept = Object.fromEntries(Object.entries(fields ?? {}).filter(([, value]) => value));
  return JSON.stringify({
    v: ITEM_FORMAT_VERSION,
    ...(type && type !== 'login' && { type }),
    site,
    username,
    password,
    notes,
    ...(totp && { totp }),
    ...(tags?.length && { tags: normalizeTags(tags) }),
    ...(favorite && { favorite: true }),
    ...(Object.keys(kept).length && { fields: kept }),
    ...(history?.length && { history }),
  });
}

export function parseItem(json: string): VaultItemData {
  const value: unknown = JSON.parse(json);
  if (typeof value !== 'object' || value === null) throw new Error('Item is not an object');
  const record = value as Record<string, unknown>;
  if (record.v !== ITEM_FORMAT_VERSION)
    throw new Error(`Unsupported item version: ${String(record.v)}`);
  const field = (name: 'site' | 'username' | 'password' | 'notes'): string => {
    const fieldValue = record[name];
    if (typeof fieldValue !== 'string') throw new Error(`Item field "${name}" is not a string`);
    return fieldValue;
  };
  const isStringRecord = (v: unknown): v is Record<string, string> =>
    typeof v === 'object' && v !== null && Object.values(v).every((s) => typeof s === 'string');
  const isHistory = (v: unknown): v is PasswordHistoryEntry[] =>
    Array.isArray(v) &&
    v.every(
      (entry) =>
        isStringRecord(entry) &&
        typeof entry.password === 'string' &&
        typeof entry.changedAt === 'string',
    );

  const { type, totp, tags, favorite, fields, history } = record;
  if (type !== undefined && !ITEM_TYPES.includes(type as ItemType))
    throw new Error(`Unsupported item type: ${String(type)}`);
  if (totp !== undefined && typeof totp !== 'string')
    throw new Error('Item field "totp" is not a string');
  if (tags !== undefined && !(Array.isArray(tags) && tags.every((t) => typeof t === 'string')))
    throw new Error('Item field "tags" is not a list of strings');
  if (favorite !== undefined && typeof favorite !== 'boolean')
    throw new Error('Item field "favorite" is not a boolean');
  if (fields !== undefined && !isStringRecord(fields))
    throw new Error('Item field "fields" is not an object of strings');
  if (history !== undefined && !isHistory(history))
    throw new Error('Item field "history" is malformed');

  // Validated above; TypeScript can't follow the throwing checks.
  const checked = {
    type: type as ItemType | undefined,
    totp: totp as string | undefined,
    tags: tags as string[] | undefined,
    favorite: favorite as boolean | undefined,
    fields: fields as Record<string, string> | undefined,
    history: history as PasswordHistoryEntry[] | undefined,
  };
  return {
    ...(checked.type && checked.type !== 'login' && { type: checked.type }),
    site: field('site'),
    username: field('username'),
    password: field('password'),
    notes: field('notes'),
    ...(checked.totp && { totp: checked.totp }),
    ...(checked.tags?.length && { tags: normalizeTags(checked.tags) }),
    ...(checked.favorite && { favorite: true }),
    ...(checked.fields && Object.keys(checked.fields).length && { fields: checked.fields }),
    ...(checked.history?.length && { history: checked.history }),
  };
}

/**
 * The data to save for an edit: if a login's password changed, the old one
 * goes into its history (oldest first, capped) with the time it was replaced.
 */
export function withPasswordHistory(
  previous: VaultItemData,
  next: VaultItemData,
  now = new Date(),
): VaultItemData {
  if (!isLogin(next) || !previous.password || previous.password === next.password) return next;
  const history = [
    ...(previous.history ?? []),
    { password: previous.password, changedAt: now.toISOString() },
  ].slice(-MAX_PASSWORD_HISTORY);
  return { ...next, history };
}

/** When the current password was set: the last replacement, else the item's creation. */
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
