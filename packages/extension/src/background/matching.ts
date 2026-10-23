/**
 * Which saved logins match a page. Background only: the Public Suffix List
 * (tldts) is far too big for the content script, whose bundle build.mjs
 * keeps small, and the content script never decides what matches anyway.
 *
 * Hosts come from siteHost / securePageHost (lower-case, punycode, "www."
 * dropped). A login matches by its `match` mode:
 * - host (default): the saved host or a subdomain of it
 * - domain: anywhere on the saved host's registrable domain ("eTLD+1")
 * - exact: the saved host only
 * - never: no page
 * A saved site that is itself a public suffix (co.uk, github.io) matches no
 * page in any mode: it isn't a website, and matching it would match every
 * site under it.
 */
import { parse } from 'tldts';
import { isLocalHost, siteHost } from '../shared/urls';
import type { MatchMode } from './items';

// Private suffixes too, so alice.github.io and bob.github.io are different sites.
const PSL = { allowPrivateDomains: true } as const;

interface Matchable {
  site: string;
  match?: MatchMode;
}

/** The registrable domain (example.co.uk for a.b.example.co.uk); null for IPs, localhost and suffixes. */
export function registrableDomain(host: string): string | null {
  const parsed = parse(host, PSL);
  return parsed.isIp ? null : parsed.domain;
}

/** Is the host a public suffix, with no registrable domain of its own? */
export function isPublicSuffix(host: string): boolean {
  if (isLocalHost(host)) return false; // tldts has no domain for it either, but it's a real host.
  const parsed = parse(host, PSL);
  return !parsed.isIp && parsed.domain === null;
}

function matchesBy(mode: Exclude<MatchMode, 'never'>, saved: string, pageHost: string): boolean {
  switch (mode) {
    case 'exact':
      return pageHost === saved;
    case 'host':
      return pageHost === saved || pageHost.endsWith(`.${saved}`);
    case 'domain': {
      const domain = registrableDomain(saved);
      // IPs and localhost have no wider domain: just that host.
      return domain ? registrableDomain(pageHost) === domain : pageHost === saved;
    }
  }
}

/** Does the login match the page? Used for everything that offers, fills or lists by page. */
export function itemMatchesHost(item: Matchable, pageHost: string): boolean {
  const mode = item.match ?? 'host';
  if (mode === 'never') return false;
  const saved = siteHost(item.site);
  if (!saved || isPublicSuffix(saved)) return false;
  return matchesBy(mode, saved, pageHost);
}

/**
 * For the save prompt's "is this login already saved?": like itemMatchesHost,
 * but a `never` login still counts, or every sign-in on that site would offer
 * to save it again as a new login.
 */
export function itemMatchesHostForSave(item: Matchable, pageHost: string): boolean {
  return itemMatchesHost(
    { site: item.site, match: item.match === 'never' ? 'host' : (item.match ?? 'host') },
    pageHost,
  );
}
