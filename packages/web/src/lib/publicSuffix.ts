/**
 * The extension never fills a login saved for a public suffix (co.uk,
 * github.io: shared suffixes, not websites). The item form uses this to say
 * so while there's still time to fix the site. The suffix list (tldts) is
 * loaded on demand, so it isn't in the main bundle.
 */

/** The host of a saved site, the way the extension reads it ("www." dropped); null if none. */
function hostOf(site: string): string | null {
  const trimmed = site.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    return (
      url.hostname
        .toLowerCase()
        .replace(/\.$/, '')
        .replace(/^www\./, '') || null
    );
  } catch {
    return null;
  }
}

/** The site's host if it's a public suffix (so it will never be filled), else null. */
export async function publicSuffixSite(site: string): Promise<string | null> {
  const host = hostOf(site);
  if (!host || host === 'localhost' || !host.includes('.')) return null;
  const { parse } = await import('tldts');
  const parsed = parse(host, { allowPrivateDomains: true });
  return !parsed.isIp && parsed.domain === null ? host : null;
}
