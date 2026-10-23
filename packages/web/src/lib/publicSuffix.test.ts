import { describe, expect, it } from 'vitest';
import { publicSuffixSite } from './publicSuffix';

describe('publicSuffixSite', () => {
  it.each([
    ['co.uk', 'co.uk'],
    ['https://github.io/login', 'github.io'],
    ['www.herokuapp.com', 'herokuapp.com'],
  ])('flags %s, which matches no website', async (site, host) => {
    expect(await publicSuffixSite(site)).toBe(host);
  });

  it.each([
    'bbc.co.uk',
    'alice.github.io',
    'https://example.com/a',
    'localhost',
    '192.168.1.10',
    '',
  ])('leaves %j alone', async (site) => {
    expect(await publicSuffixSite(site)).toBeNull();
  });
});
