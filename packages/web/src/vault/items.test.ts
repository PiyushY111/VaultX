import { describe, expect, it } from 'vitest';
import { filterItems, parseItem, serializeItem, type VaultItem } from './items';

const item = (site: string, username = '', notes = '', password = 'pw'): VaultItem => ({
  id: site,
  site,
  username,
  password,
  notes,
  createdAt: '',
  updatedAt: '',
});

describe('serializeItem / parseItem', () => {
  it('round-trips and tags the format version', () => {
    const data = {
      site: 'example.com',
      username: 'alice',
      password: 'p@ss "quoted"',
      notes: 'line1\nline2',
    };
    const json = serializeItem(data);
    expect(JSON.parse(json).v).toBe(1);
    expect(parseItem(json)).toEqual(data);
  });

  it('drops unexpected fields when serializing', () => {
    const json = serializeItem({ ...item('a.com'), id: 'x' } as never);
    expect(Object.keys(JSON.parse(json)).sort()).toEqual([
      'notes',
      'password',
      'site',
      'username',
      'v',
    ]);
  });

  it.each([
    ['not an object', '"str"'],
    ['wrong version', JSON.stringify({ v: 2, site: '', username: '', password: '', notes: '' })],
    ['missing field', JSON.stringify({ v: 1, site: '', username: '', password: '' })],
    ['non-string field', JSON.stringify({ v: 1, site: 1, username: '', password: '', notes: '' })],
  ])('rejects %s', (_, json) => {
    expect(() => parseItem(json)).toThrow();
  });
});

describe('filterItems', () => {
  const items = [
    item('GitHub', 'octocat', 'work account', 'secret-github'),
    item('bank.example.com', 'alice'),
    item('Email', 'alice@example.com', 'personal'),
  ];

  it('sorts by site when there is no query', () => {
    expect(filterItems(items, '  ').map((i) => i.site)).toEqual([
      'bank.example.com',
      'Email',
      'GitHub',
    ]);
  });

  it('matches site, username and notes case-insensitively', () => {
    expect(filterItems(items, 'github').map((i) => i.site)).toEqual(['GitHub']);
    expect(filterItems(items, 'ALICE').map((i) => i.site)).toEqual(['bank.example.com', 'Email']);
    expect(filterItems(items, 'personal').map((i) => i.site)).toEqual(['Email']);
  });

  it('never matches against passwords', () => {
    expect(filterItems(items, 'secret-github')).toEqual([]);
  });
});
