import { describe, expect, it } from 'vitest';
import {
  MATCH_MODES,
  MAX_FOLDER_DEPTH,
  MAX_FOLDER_SEGMENT,
  TRASH_RETENTION_DAYS,
  isTrashed,
  normalizeFolder,
  normalizeTags,
  parseItem,
  serializeItem,
  trashExpired,
  withPasswordHistory,
  type VaultItemData,
} from '../src/index.js';

const data = { site: 'github.com', username: 'u', password: 'p', notes: '' };

describe('serializeItem / parseItem', () => {
  it('round-trips and tags the format version', () => {
    const item = {
      site: 'example.com',
      username: 'alice',
      password: 'p@ss "quoted"',
      notes: 'line1\nline2',
    };
    const json = serializeItem(item);
    expect(JSON.parse(json).v).toBe(1);
    expect(parseItem(json)).toEqual(item);
  });

  it('drops properties of the in-memory item that aren’t part of the format', () => {
    const json = serializeItem({ ...data, id: 'x', revision: 3, createdAt: '' } as never);
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
    ['null', 'null'],
    ['wrong version', JSON.stringify({ v: 2, site: '', username: '', password: '', notes: '' })],
    ['missing field', JSON.stringify({ v: 1, site: '', username: '', password: '' })],
    ['non-string field', JSON.stringify({ v: 1, site: 1, username: '', password: '', notes: '' })],
  ])('rejects %s', (_, json) => {
    expect(() => parseItem(json)).toThrow();
  });
});

describe('two-factor secrets in items', () => {
  it('are left out of the JSON when empty, so older items encrypt exactly as before', () => {
    expect(serializeItem(data)).toBe(
      '{"v":1,"site":"github.com","username":"u","password":"p","notes":""}',
    );
    expect(serializeItem({ ...data, totp: '' })).toBe(serializeItem(data));
    expect(parseItem(serializeItem(data))).toEqual(data);
  });

  it('round-trip when set', () => {
    const withTotp = { ...data, totp: 'JBSWY3DPEHPK3PXP' };
    expect(JSON.parse(serializeItem(withTotp)).totp).toBe('JBSWY3DPEHPK3PXP');
    expect(parseItem(serializeItem(withTotp))).toEqual(withTotp);
  });

  it('must be a string', () => {
    expect(() => parseItem(JSON.stringify({ v: 1, ...data, totp: 5 }))).toThrow(/totp/);
  });
});

describe('item kinds, tags, favorites and history', () => {
  it('leaves every optional field out of the JSON when unset, so old items encrypt as before', () => {
    expect(
      serializeItem({
        ...data,
        type: 'login',
        tags: [],
        favorite: false,
        fields: {},
        history: [],
        extra: {},
      }),
    ).toBe(serializeItem(data));
  });

  it('round-trips a card with tags, a favorite flag and a history', () => {
    const card = {
      ...data,
      type: 'card' as const,
      tags: ['Work', 'travel'],
      favorite: true,
      fields: { cardholder: 'A. Person', number: '4111 1111 1111 1111', expiry: '12/30', cvv: '' },
      history: [{ password: 'old', changedAt: '2026-01-01T00:00:00.000Z' }],
    };
    const parsed = parseItem(serializeItem(card));
    // Empty card fields are dropped; everything else comes back as it went in.
    expect(parsed).toEqual({
      ...card,
      fields: { cardholder: 'A. Person', number: '4111 1111 1111 1111', expiry: '12/30' },
    });
  });

  it.each([
    ['an unknown type', { type: 'wallet' }],
    ['tags that are not strings', { tags: [1] }],
    ['a non-boolean favorite', { favorite: 'yes' }],
    ['non-string fields', { fields: { number: 4111 } }],
    ['a malformed history', { history: [{ password: 'x' }] }],
  ])('rejects %s', (_, bad) => {
    expect(() => parseItem(JSON.stringify({ v: 1, ...data, ...bad }))).toThrow();
  });

  it('normalizes tags: trims, drops empties and case-insensitive repeats', () => {
    expect(normalizeTags(' work, Personal ,, WORK ,personal')).toEqual(['work', 'Personal']);
  });

  it('records the old password when a login’s password changes, keeping the last 10', () => {
    const now = new Date('2026-09-28T00:00:00.000Z');
    const unchanged = withPasswordHistory(data, { ...data, notes: 'edited' }, now);
    expect(unchanged.history).toBeUndefined();
    let item: VaultItemData = data;
    for (let i = 1; i <= 12; i++)
      item = withPasswordHistory(item, { ...item, password: `p${i}` }, now);
    expect(item.history).toHaveLength(10);
    expect(item.history!.map((entry) => entry.password)).toEqual([
      'p2',
      'p3',
      'p4',
      'p5',
      'p6',
      'p7',
      'p8',
      'p9',
      'p10',
      'p11',
    ]);
    expect(item.history![0]!.changedAt).toBe(now.toISOString());
    // Notes and cards have no password history.
    expect(
      withPasswordHistory({ ...data, type: 'note' }, { ...data, type: 'note', password: 'x' })
        .history,
    ).toBeUndefined();
  });
});

describe('fields from newer versions', () => {
  const future = {
    v: 1,
    ...data,
    futureLabel: 'Work/Servers',
    futureFlag: null,
    futureNested: { a: [1, 2] },
  };

  it('are kept in `extra` when parsing', () => {
    expect(parseItem(JSON.stringify(future))).toEqual({
      ...data,
      extra: { futureLabel: 'Work/Servers', futureFlag: null, futureNested: { a: [1, 2] } },
    });
  });

  it('survive a parse → serialize round trip with the same keys and values', () => {
    const json = serializeItem(parseItem(JSON.stringify(future)));
    expect(JSON.parse(json)).toEqual(future);
  });

  it('go after the known fields, in their original order', () => {
    const json = JSON.stringify({ zeta: 1, v: 1, ...data, alpha: 2 });
    expect(Object.keys(JSON.parse(serializeItem(parseItem(json))))).toEqual([
      'v',
      'site',
      'username',
      'password',
      'notes',
      'zeta',
      'alpha',
    ]);
  });

  it('can’t override a known field when serializing', () => {
    const json = serializeItem({
      ...data,
      extra: { v: 9, password: 'stolen', site: 'evil.example', tags: ['x'], keep: true },
    });
    expect(JSON.parse(json)).toEqual({ v: 1, ...data, keep: true });
  });

  it('can’t change the prototype of the parsed item', () => {
    const parsed = parseItem(
      `{"v":1,"site":"","username":"","password":"","notes":"","__proto__":{"x":1}}`,
    );
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(parsed.extra)).toBe(Object.prototype);
    expect((parsed as { x?: unknown }).x).toBeUndefined();
    expect(serializeItem(parsed)).toContain('"__proto__":{"x":1}');
  });

  it('are kept when a password change adds to the history', () => {
    const previous = parseItem(JSON.stringify(future));
    const next = withPasswordHistory(previous, { ...previous, password: 'new' }, new Date(0));
    expect(next.extra).toEqual(previous.extra);
    expect(next.history).toHaveLength(1);
  });

  it('leave items without them encrypting byte-for-byte as before', () => {
    const full = {
      ...data,
      totp: 'JBSWY3DPEHPK3PXP',
      tags: ['a'],
      favorite: true,
      history: [{ password: 'old', changedAt: '2026-01-01T00:00:00.000Z' }],
    };
    expect(serializeItem(parseItem(serializeItem(full)))).toBe(
      '{"v":1,"site":"github.com","username":"u","password":"p","notes":"",' +
        '"totp":"JBSWY3DPEHPK3PXP","tags":["a"],"favorite":true,' +
        '"history":[{"password":"old","changedAt":"2026-01-01T00:00:00.000Z"}]}',
    );
  });
});

describe('the trash', () => {
  const deletedAt = '2026-10-01T12:00:00.000Z';
  const day = 24 * 60 * 60 * 1000;

  it('round-trips deletedAt, and leaves it out for live items', () => {
    const trashed = { ...data, deletedAt };
    expect(parseItem(serializeItem(trashed))).toEqual(trashed);
    expect(JSON.parse(serializeItem(trashed)).deletedAt).toBe(deletedAt);
    expect(serializeItem({ ...data, deletedAt: '' })).toBe(serializeItem(data));
    expect(parseItem(serializeItem(trashed)).extra).toBeUndefined();
  });

  it.each([5, null, 'yesterday', '2026-13-45T00:00:00Z'])('rejects deletedAt %j', (bad) => {
    expect(() => parseItem(JSON.stringify({ v: 1, ...data, deletedAt: bad }))).toThrow(/deletedAt/);
  });

  it('tells trashed items apart', () => {
    expect(isTrashed(data)).toBe(false);
    expect(isTrashed({ ...data, deletedAt })).toBe(true);
  });

  it(`expires items ${TRASH_RETENTION_DAYS} days after they were trashed`, () => {
    const trashed = { ...data, deletedAt };
    const at = (ms: number) => new Date(Date.parse(deletedAt) + ms);
    expect(trashExpired(data, at(365 * day))).toBe(false);
    expect(trashExpired(trashed, at(TRASH_RETENTION_DAYS * day - 1))).toBe(false);
    expect(trashExpired(trashed, at(TRASH_RETENTION_DAYS * day))).toBe(true);
  });
});

describe('folders', () => {
  it('normalize: trims each level and drops empty ones', () => {
    expect(normalizeFolder(' Work / / Servers/ ')).toBe('Work/Servers');
    expect(normalizeFolder('Personal')).toBe('Personal');
    expect(normalizeFolder('')).toBeUndefined();
    expect(normalizeFolder(' / ')).toBeUndefined();
  });

  it(`refuse more than ${MAX_FOLDER_DEPTH} levels or ${MAX_FOLDER_SEGMENT}-character names`, () => {
    expect(normalizeFolder(Array(MAX_FOLDER_DEPTH).fill('a').join('/'))).toBeDefined();
    expect(() =>
      normalizeFolder(
        Array(MAX_FOLDER_DEPTH + 1)
          .fill('a')
          .join('/'),
      ),
    ).toThrow(RangeError);
    expect(normalizeFolder('x'.repeat(MAX_FOLDER_SEGMENT))).toBeDefined();
    expect(() => normalizeFolder('x'.repeat(MAX_FOLDER_SEGMENT + 1))).toThrow(RangeError);
  });

  it('round-trip, normalized, and are left out when empty', () => {
    expect(parseItem(serializeItem({ ...data, folder: 'Work/Servers' }))).toEqual({
      ...data,
      folder: 'Work/Servers',
    });
    expect(JSON.parse(serializeItem({ ...data, folder: ' Work /Servers ' })).folder).toBe(
      'Work/Servers',
    );
    expect(serializeItem({ ...data, folder: ' / ' })).toBe(serializeItem(data));
  });

  it.each([5, ['Work'], 'a/b/c/d/e/f', 'x'.repeat(MAX_FOLDER_SEGMENT + 1)])(
    'reject a stored folder of %j',
    (bad) => {
      expect(() => parseItem(JSON.stringify({ v: 1, ...data, folder: bad }))).toThrow(/folder/);
    },
  );
});

describe('match modes', () => {
  it.each(MATCH_MODES.filter((mode) => mode !== 'host'))('round-trip %s', (match) => {
    expect(parseItem(serializeItem({ ...data, match }))).toEqual({ ...data, match });
  });

  it('leave the default (host) out of the JSON, so items encrypt as before', () => {
    expect(serializeItem({ ...data, match: 'host' })).toBe(serializeItem(data));
    expect(parseItem(JSON.stringify({ v: 1, ...data, match: 'host' }))).toEqual(data);
  });

  it.each(['subdomain', 5, null])('reject %j', (bad) => {
    expect(() => parseItem(JSON.stringify({ v: 1, ...data, match: bad }))).toThrow(/match/);
  });
});
