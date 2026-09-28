import { LEGACY_ITEM_REVISION, decryptItem, encryptItem } from '@password-manager/crypto';
import type { ItemResponse, ItemRevisionPayload } from '../api';
import { fromBase64, toBase64 } from '../lib/base64';
import type { RevisionLedger } from './revisionLedger';

// The item format is shared with packages/extension/src/background/items.ts
// (the extension's test/interop.test.ts checks the two stay compatible).

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
  /** Card and identity details, keyed as in {@link CARD_FIELDS} and {@link IDENTITY_FIELDS}. */
  fields?: Record<string, string>;
  /** Earlier passwords, oldest first. Kept to {@link MAX_PASSWORD_HISTORY}. */
  history?: PasswordHistoryEntry[];
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

export const MAX_PASSWORD_HISTORY = 10;

export const CARD_FIELDS: readonly [key: string, label: string, secret?: boolean][] = [
  ['cardholder', 'Name on card'],
  ['number', 'Card number', true],
  ['expiry', 'Expiry (MM/YY)'],
  ['cvv', 'Security code', true],
];

export const IDENTITY_FIELDS: readonly [key: string, label: string][] = [
  ['firstName', 'First name'],
  ['lastName', 'Last name'],
  ['email', 'Email'],
  ['phone', 'Phone'],
  ['address', 'Address'],
  ['city', 'City'],
  ['postalCode', 'Postal code'],
  ['country', 'Country'],
];

export const emptyItem = (type: ItemType = 'login'): VaultItemData => ({
  ...(type !== 'login' && { type }),
  site: '',
  username: '',
  password: '',
  notes: '',
});

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
}

/**
 * Case-insensitive search over decrypted, in-memory items only. Matches the
 * title/site, username, notes, tags and card/identity details; never
 * passwords or card security codes. Favorites come first.
 */
export function filterItems(
  items: VaultItem[],
  query: string,
  { tag = null, favoritesOnly = false }: ItemFilter = {},
): VaultItem[] {
  const needle = query.trim().toLowerCase();
  const sorted = [...items].sort(
    (a, b) =>
      Number(Boolean(b.favorite)) - Number(Boolean(a.favorite)) ||
      a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }),
  );
  return sorted.filter((item) => {
    if (favoritesOnly && !item.favorite) return false;
    if (tag && !item.tags?.some((t) => t.toLowerCase() === tag.toLowerCase())) return false;
    if (!needle) return true;
    const haystack = [
      item.site,
      item.username,
      item.notes,
      ...(item.tags ?? []),
      ...Object.entries(item.fields ?? {})
        .filter(([key]) => key !== 'cvv')
        .map(([, value]) => value),
    ];
    return haystack.some((value) => value.toLowerCase().includes(needle));
  });
}
