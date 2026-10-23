/**
 * The vault item format: the JSON inside each encrypted item. Shared by the
 * web vault and the extension, so both read and write exactly the same thing.
 *
 * Rules for changing it (see DESIGN.md):
 * - New fields are optional and left out of the JSON when empty, so items
 *   that don't use them encrypt exactly as before.
 * - Fields this version doesn't know are kept in `extra` and written back
 *   unchanged, so saving an item never removes what a newer client added.
 *   A new field gets its key added to KNOWN_KEYS and is validated in
 *   parseItem like the others.
 */

export type ItemType = 'login' | 'note' | 'card' | 'identity';

/**
 * How a login matches pages (see the extension's background/matching.ts):
 * - `host` (the default): the saved host and its subdomains
 * - `domain`: anywhere on the same registrable domain (example.com)
 * - `exact`: the saved host only
 * - `never`: never offered or filled on a page (still listed and copyable)
 */
export type MatchMode = 'host' | 'domain' | 'exact' | 'never';
export const MATCH_MODES: readonly MatchMode[] = ['host', 'domain', 'exact', 'never'];
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
  /**
   * When the item was moved to the trash (ISO 8601). Absent for live items.
   * Trashed items are hidden everywhere except the trash, and the web vault
   * deletes them for good {@link TRASH_RETENTION_DAYS} days later.
   */
  deletedAt?: string;
  /**
   * The item's folder: levels joined by "/" ("Work/Servers"), as
   * {@link normalizeFolder} leaves them. Absent when it's in no folder.
   */
  folder?: string;
  /** How a login matches pages; absent means `host`. */
  match?: MatchMode;
  /**
   * Fields this version doesn't know, kept as-is so saving the item doesn't
   * remove what a newer client added. Never shown, searched or edited.
   */
  extra?: Record<string, unknown>;
}

/** Version tag inside the encrypted JSON, so the item format can evolve. */
const ITEM_FORMAT_VERSION = 1;

/** Every key this version reads; anything else in an item goes to `extra`. */
const KNOWN_KEYS: ReadonlySet<string> = new Set([
  'v',
  'type',
  'site',
  'username',
  'password',
  'notes',
  'totp',
  'tags',
  'favorite',
  'fields',
  'history',
  'deletedAt',
  'folder',
  'match',
]);

export const MAX_PASSWORD_HISTORY = 10;

/** How long an item stays in the trash before the web vault deletes it for good. */
export const TRASH_RETENTION_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Folder paths: at most this many levels, each at most this many characters. */
export const MAX_FOLDER_DEPTH = 5;
export const MAX_FOLDER_SEGMENT = 64;

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

export const isLogin = (item: Pick<VaultItemData, 'type'>): boolean =>
  !item.type || item.type === 'login';

export const isTrashed = (item: VaultItemData): boolean => Boolean(item.deletedAt);

/** In the trash for at least {@link TRASH_RETENTION_DAYS} days, so due to be deleted. */
export const trashExpired = (item: VaultItemData, now: Date): boolean =>
  isTrashed(item) && now.getTime() - Date.parse(item.deletedAt!) >= TRASH_RETENTION_DAYS * DAY_MS;

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

/**
 * " Work / / Servers/ " → "Work/Servers": each level trimmed, empty levels
 * dropped; undefined when nothing is left (no folder). Throws a RangeError
 * past {@link MAX_FOLDER_DEPTH} levels or {@link MAX_FOLDER_SEGMENT}
 * characters per level.
 */
export function normalizeFolder(input: string): string | undefined {
  const levels = input
    .split('/')
    .map((level) => level.trim())
    .filter(Boolean);
  if (levels.length > MAX_FOLDER_DEPTH)
    throw new RangeError(`Folders can be at most ${MAX_FOLDER_DEPTH} levels deep`);
  if (levels.some((level) => level.length > MAX_FOLDER_SEGMENT))
    throw new RangeError(`Folder names can be at most ${MAX_FOLDER_SEGMENT} characters`);
  return levels.length ? levels.join('/') : undefined;
}

/**
 * The entries of `record` whose keys this version doesn't know. Built with
 * Object.fromEntries, so a "__proto__" key stays an ordinary property.
 */
const unknownEntries = (record: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(record).filter(([key]) => !KNOWN_KEYS.has(key)));

export function serializeItem(data: VaultItemData): string {
  const {
    type,
    site,
    username,
    password,
    notes,
    totp,
    tags,
    favorite,
    fields,
    history,
    deletedAt,
    folder,
    match,
    extra,
  } = data;
  const folderPath = folder ? normalizeFolder(folder) : undefined;
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
    ...(deletedAt && { deletedAt }),
    ...(folderPath && { folder: folderPath }),
    ...(match && match !== 'host' && { match }),
    // Last, and filtered, so `extra` can never replace a known field.
    ...(extra && unknownEntries(extra)),
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

  const { type, totp, tags, favorite, fields, history, deletedAt, folder, match } = record;
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
  if (deletedAt !== undefined && !(typeof deletedAt === 'string' && Date.parse(deletedAt)))
    throw new Error('Item field "deletedAt" is not a date');
  if (match !== undefined && !MATCH_MODES.includes(match as MatchMode))
    throw new Error(`Unsupported item field "match": ${String(match)}`);
  const matchMode = match as MatchMode | undefined;
  let folderPath: string | undefined;
  if (folder !== undefined) {
    if (typeof folder !== 'string') throw new Error('Item field "folder" is not a string');
    try {
      folderPath = normalizeFolder(folder);
    } catch (error) {
      throw new Error(`Item field "folder" is invalid: ${(error as Error).message}`, {
        cause: error,
      });
    }
  }

  // Validated above; TypeScript can't follow the throwing checks.
  const checked = {
    type: type as ItemType | undefined,
    totp: totp as string | undefined,
    tags: tags as string[] | undefined,
    favorite: favorite as boolean | undefined,
    fields: fields as Record<string, string> | undefined,
    history: history as PasswordHistoryEntry[] | undefined,
    deletedAt: deletedAt as string | undefined,
  };
  const extra = unknownEntries(record);
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
    ...(checked.deletedAt && { deletedAt: checked.deletedAt }),
    ...(folderPath && { folder: folderPath }),
    ...(matchMode && matchMode !== 'host' && { match: matchMode }),
    ...(Object.keys(extra).length && { extra }),
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
