import { describe, expect, it } from 'vitest';
import {
  isPublicSuffix,
  itemMatchesHost,
  itemMatchesHostForSave,
  registrableDomain,
} from '../src/background/matching';
import type { MatchMode } from '../src/background/items';

const matches = (site: string, match: MatchMode | undefined, pageHost: string) =>
  itemMatchesHost({ site, ...(match && { match }) }, pageHost);

describe('itemMatchesHost', () => {
  it.each([
    // The default, as before: the saved host and its subdomains.
    ['example.com', undefined, 'example.com', true],
    ['example.com', undefined, 'login.example.com', true],
    ['https://www.example.com', undefined, 'example.com', true],
    ['example.com', 'host', 'a.b.example.com', true],
    ['example.com', 'host', 'example.com.evil.net', false],
    ['example.com', 'host', 'notexample.com', false],
    ['example.com', 'host', 'examp1e.com', false],
    ['login.example.com', 'host', 'example.com', false],
    ['com', 'host', 'example.com', false],
    // Public suffixes never match, in any mode.
    ['co.uk', 'host', 'bbc.co.uk', false],
    ['co.uk', 'domain', 'bbc.co.uk', false],
    ['github.io', 'host', 'alice.github.io', false],
    ['https://github.io/login', 'exact', 'github.io', false],
    // Domain: the whole registrable domain, private suffixes included.
    ['login.example.co.uk', 'domain', 'www.example.co.uk', true],
    ['login.example.co.uk', 'domain', 'example.co.uk', true],
    ['login.example.co.uk', 'domain', 'other.co.uk', false],
    ['alice.github.io', 'domain', 'bob.github.io', false],
    ['alice.github.io', 'domain', 'docs.alice.github.io', true],
    // Exact: that host only (www. is still ignored, as everywhere).
    ['login.example.com', 'exact', 'login.example.com', true],
    ['login.example.com', 'exact', 'a.login.example.com', false],
    ['www.example.com', 'exact', 'example.com', true],
    // Never: nothing.
    ['example.com', 'never', 'example.com', false],
    // Local development and IP addresses: domain falls back to the exact host.
    ['localhost', 'host', 'localhost', true],
    ['localhost', 'domain', 'localhost', true],
    ['192.168.1.10', 'domain', '192.168.1.10', true],
    ['192.168.1.10', 'domain', '192.168.1.11', false],
    ['http://127.0.0.1:8080', 'host', '127.0.0.1', true],
    // Internationalized names compare as punycode.
    ['bücher.example', 'host', 'xn--bcher-kva.example', true],
  ] as const)('%s (%s) on %s → %s', (site, match, page, expected) => {
    expect(matches(site, match, page)).toBe(expected);
  });

  it('never matches a site that isn’t a host', () => {
    expect(matches('', undefined, 'example.com')).toBe(false);
    expect(matches('not a url at all', undefined, 'example.com')).toBe(false);
  });
});

describe('itemMatchesHostForSave', () => {
  it('still recognizes a “never” login, so the save prompt doesn’t offer a duplicate', () => {
    expect(itemMatchesHostForSave({ site: 'example.com', match: 'never' }, 'example.com')).toBe(
      true,
    );
    expect(itemMatchesHostForSave({ site: 'co.uk', match: 'never' }, 'bbc.co.uk')).toBe(false);
  });
});

describe('the public suffix list', () => {
  it('knows ICANN and private suffixes, and that localhost and IPs aren’t suffixes', () => {
    expect(['co.uk', 'github.io', 'herokuapp.com'].map(isPublicSuffix)).toEqual([true, true, true]);
    expect(['example.co.uk', 'localhost', '10.0.0.1'].map(isPublicSuffix)).toEqual([
      false,
      false,
      false,
    ]);
  });

  it('finds the registrable domain', () => {
    expect(registrableDomain('a.b.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('docs.alice.github.io')).toBe('alice.github.io');
    expect(registrableDomain('192.168.1.10')).toBeNull();
    expect(registrableDomain('localhost')).toBeNull();
  });
});
