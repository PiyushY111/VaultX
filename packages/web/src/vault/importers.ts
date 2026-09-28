import { parseCsv } from '../lib/csv';
import { readTotp } from '../lib/useTotp';
import type { VaultItemData } from './items';

/**
 * Turns another password manager's CSV export into vault items. The file is
 * read in the browser; nothing is sent until the items are encrypted.
 */

export type ImportSource = 'Chrome' | 'Firefox' | 'Bitwarden' | '1Password' | 'CSV';

export interface ParsedImport {
  source: ImportSource;
  items: VaultItemData[];
  /** Rows left out: not a login (cards, notes…), or nothing to save. */
  skipped: number;
}

// Each field's column names across exporters, lower-cased:
// Chrome/Edge/Brave:  name,url,username,password,note
// Firefox:            url,username,password,httpRealm,formActionOrigin,guid,…
// Bitwarden:          folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
// 1Password 8:        Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
const COLUMNS = {
  name: ['name', 'title'],
  url: ['url', 'login_uri', 'website', 'urls'],
  username: ['username', 'login_username', 'user name', 'email'],
  password: ['password', 'login_password'],
  notes: ['note', 'notes'],
  totp: ['login_totp', 'otpauth', 'totp', 'one-time password'],
  type: ['type'],
} as const;

function detectSource(headers: string[]): ImportSource {
  const has = (name: string) => headers.includes(name);
  if (has('login_uri') && has('login_password')) return 'Bitwarden';
  if (has('httprealm') || has('formactionorigin')) return 'Firefox';
  if (has('title') && has('otpauth')) return '1Password';
  if (has('name') && has('url') && has('username') && has('password')) return 'Chrome';
  return 'CSV';
}

/** The site to store: the URL's host (what autofill matches on), else the URL, else the name. */
function siteFor(url: string, name: string): string {
  const candidate = url.split(/[\s,]+/)[0] ?? ''; // Some exports list several URLs.
  if (candidate) {
    try {
      const { protocol, hostname } = new URL(
        candidate.includes('://') ? candidate : `https://${candidate}`,
      );
      if (/^https?:$/.test(protocol) && hostname) return hostname.replace(/^www\./, '');
    } catch {
      // Not a URL; keep it as typed.
    }
    return candidate;
  }
  return name;
}

export function parseImport(text: string): ParsedImport {
  const rows = parseCsv(text);
  if (rows.length === 0) throw new Error('The file is empty.');
  const headers = rows[0]!.map((header) => header.trim().toLowerCase());
  const index = (names: readonly string[]) => {
    for (const name of names) {
      const at = headers.indexOf(name);
      if (at !== -1) return at;
    }
    return -1;
  };
  const at = Object.fromEntries(
    Object.entries(COLUMNS).map(([field, names]) => [field, index(names)]),
  ) as Record<keyof typeof COLUMNS, number>;
  if (at.password === -1 || (at.url === -1 && at.name === -1)) {
    throw new Error(
      'This doesn’t look like a password export: it needs a password column and a URL or name column.',
    );
  }

  const items: VaultItemData[] = [];
  let skipped = 0;
  for (const row of rows.slice(1)) {
    const get = (column: number) => (column === -1 ? '' : (row[column] ?? '').trim());
    // Bitwarden also exports cards, identities and notes.
    if (at.type !== -1 && get(at.type) && get(at.type).toLowerCase() !== 'login') {
      skipped++;
      continue;
    }
    const name = get(at.name);
    const url = get(at.url);
    const username = get(at.username);
    const password = row[at.password] ?? ''; // Passwords keep their spaces.
    const site = siteFor(url, name);
    if (!site || (!password && !username)) {
      skipped++;
      continue;
    }
    // There's no separate field for the name, so keep it in the notes.
    const extras = [
      name && name.toLowerCase() !== site.toLowerCase() && name !== url ? `Name: ${name}` : '',
    ].filter(Boolean);
    const notes = [get(at.notes), ...extras].filter(Boolean).join('\n');
    const totp = get(at.totp);
    // A secret that doesn't parse still goes in, in the notes, so nothing is lost.
    if (totp && typeof readTotp(totp) === 'string') {
      items.push({
        site,
        username,
        password,
        notes: [notes, `TOTP: ${totp}`].filter(Boolean).join('\n'),
      });
    } else {
      items.push({ site, username, password, notes, ...(totp && { totp }) });
    }
  }
  return { source: detectSource(headers), items, skipped };
}

/** Leaves out items already in the vault (same site, username and password) and repeats within the file. */
export function withoutDuplicates(
  incoming: VaultItemData[],
  existing: readonly VaultItemData[],
): { items: VaultItemData[]; duplicates: number } {
  const key = (item: VaultItemData) =>
    JSON.stringify([item.site.toLowerCase(), item.username, item.password]);
  const seen = new Set(existing.map(key));
  const items: VaultItemData[] = [];
  for (const item of incoming) {
    const k = key(item);
    if (seen.has(k)) continue;
    seen.add(k);
    items.push(item);
  }
  return { items, duplicates: incoming.length - items.length };
}
