import { describe, expect, it } from 'vitest';
import { normalizeServerUrl, securePageHost, siteHost } from '../src/shared/urls';

describe('siteHost', () => {
  it.each([
    ['github.com', 'github.com'],
    ['https://github.com/login', 'github.com'],
    ['  GitHub.com  ', 'github.com'],
    ['www.example.com', 'example.com'],
    ['http://localhost:5173/', 'localhost'],
    ['127.0.0.1', '127.0.0.1'],
  ])('%s → %s', (site, host) => {
    expect(siteHost(site)).toBe(host);
  });

  it.each(['', '   ', 'com', 'not a url at all', 'https://'])('rejects %j', (site) => {
    expect(siteHost(site)).toBeNull();
  });
});

describe('securePageHost', () => {
  it('allows https and localhost http', () => {
    expect(securePageHost('https://accounts.example.com/login?next=/')).toBe(
      'accounts.example.com',
    );
    expect(securePageHost('http://localhost:3000/login')).toBe('localhost');
    expect(securePageHost('http://127.0.0.1:8080/')).toBe('127.0.0.1');
  });

  it.each([
    'http://example.com/login',
    'file:///etc/passwd',
    'chrome://settings',
    'javascript:alert(1)',
    'garbage',
  ])('refuses %s', (url) => {
    expect(securePageHost(url)).toBeNull();
  });
});

// Matching moved to background/matching.ts (test/matching.test.ts).

describe('normalizeServerUrl', () => {
  it('accepts https and localhost http, trimming trailing slashes', () => {
    expect(normalizeServerUrl('https://vault.example.com/')).toBe('https://vault.example.com');
    expect(normalizeServerUrl('https://example.com/pm/api//')).toBe('https://example.com/pm/api');
    expect(normalizeServerUrl('http://127.0.0.1:3001')).toBe('http://127.0.0.1:3001');
  });

  it.each([
    'http://vault.example.com',
    'ftp://x.com',
    'not a url',
    'https://user:pw@x.com',
    'https://x.com/?q=1',
  ])('rejects %s', (url) => {
    expect(() => normalizeServerUrl(url)).toThrow();
  });
});
