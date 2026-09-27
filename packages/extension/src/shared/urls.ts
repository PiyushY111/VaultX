/**
 * URL and domain rules shared by the background and content scripts.
 *
 * Matching is by hostname: a saved item for `example.com` matches
 * `example.com`, `www.example.com` and `login.example.com`, but not
 * `example.com.evil.net` or `notexample.com`. There is no public-suffix list,
 * so single-label hosts (`com`) are never treated as matchable, but a saved
 * site like `co.uk` would match every `*.co.uk` host — don't save those.
 */

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export const isLocalHost = (hostname: string): boolean => LOCAL_HOSTS.has(hostname);

/** Autofill, save prompts, and the server connection all require https (or localhost for development). */
export function isSecureUrl(url: URL): boolean {
  return url.protocol === 'https:' || (url.protocol === 'http:' && isLocalHost(url.hostname));
}

const stripWww = (host: string): string => host.replace(/^www\./, '');

function normalizeHost(hostname: string): string | null {
  const host = stripWww(hostname.toLowerCase().replace(/\.$/, ''));
  // Refuse single-label hosts (e.g. "com") except localhost.
  if (!host || (!host.includes('.') && !host.includes(':') && host !== 'localhost')) return null;
  return host;
}

/** Hostname of a saved item's `site` field, which may be a bare domain or a full URL. */
export function siteHost(site: string): string | null {
  const trimmed = site.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    return normalizeHost(url.hostname);
  } catch {
    return null;
  }
}

/** Hostname of a page URL, or null if autofill must not run there (non-http(s), or insecure). */
export function securePageHost(pageUrl: string): string | null {
  try {
    const url = new URL(pageUrl);
    return isSecureUrl(url) ? normalizeHost(url.hostname) : null;
  } catch {
    return null;
  }
}

/** Does a saved site match the page host (same host or a subdomain of it)? */
export function siteMatchesHost(site: string, pageHost: string): boolean {
  const saved = siteHost(site);
  if (!saved) return false;
  return pageHost === saved || pageHost.endsWith(`.${saved}`);
}

/** Validates and normalizes a server URL (origin + optional path, no trailing slash). */
export function normalizeServerUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error('Server URL is not a valid URL');
  }
  if (!isSecureUrl(url))
    throw new Error('Server URL must use https (http is allowed only for localhost)');
  if (url.username || url.password || url.search || url.hash)
    throw new Error('Server URL must not contain credentials, a query, or a fragment');
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}
