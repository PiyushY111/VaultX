/**
 * Checks passwords against Have I Been Pwned's Pwned Passwords using its
 * k-anonymity range API: only the first five characters of each password's
 * SHA-1 hash are sent; the service returns every known hash with that
 * prefix, and the comparison happens here. Neither the password nor its full
 * hash leaves the browser, but the service does learn that someone checked
 * some passwords, so this is opt-in.
 */

export const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

const PREFIX_LENGTH = 5;

export async function sha1Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export interface BreachCheckOptions {
  fetch?: typeof fetch;
  /** Requests in flight at once. */
  concurrency?: number;
  onProgress?: (done: number, total: number) => void;
}

/**
 * How many known breaches each password appears in (0 for none). Passwords
 * that share a hash prefix are checked with one request.
 */
export async function checkBreaches(
  passwords: readonly string[],
  { fetch: fetchImpl = fetch, concurrency = 4, onProgress }: BreachCheckOptions = {},
): Promise<Map<string, number>> {
  const byPrefix = new Map<string, { password: string; suffix: string }[]>();
  for (const password of new Set(passwords.filter(Boolean))) {
    const hash = (await sha1Hex(password)).toUpperCase();
    const prefix = hash.slice(0, PREFIX_LENGTH);
    const group = byPrefix.get(prefix) ?? [];
    group.push({ password, suffix: hash.slice(PREFIX_LENGTH) });
    byPrefix.set(prefix, group);
  }

  const result = new Map<string, number>();
  const queue = [...byPrefix.entries()];
  let done = 0;
  async function worker() {
    for (let next = queue.shift(); next; next = queue.shift()) {
      const [prefix, group] = next;
      const response = await fetchImpl(`${HIBP_RANGE_URL}${prefix}`, {
        // The service pads every response to a similar size, so its length
        // can't hint at which prefix was asked for.
        headers: { 'Add-Padding': 'true' },
        credentials: 'omit',
        cache: 'no-store',
      });
      if (!response.ok) {
        throw new Error(`Have I Been Pwned couldn’t be reached (HTTP ${response.status}).`);
      }
      const counts = new Map<string, number>();
      for (const line of (await response.text()).split(/\r?\n/)) {
        const [suffix, count] = line.trim().split(':');
        if (suffix && count) counts.set(suffix.toUpperCase(), Number(count));
      }
      for (const { password, suffix } of group) result.set(password, counts.get(suffix) ?? 0);
      onProgress?.(++done, byPrefix.size);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  return result;
}
