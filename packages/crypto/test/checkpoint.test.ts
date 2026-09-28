import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  compareCheckpoints,
  formatCheckpoint,
  parseCheckpoint,
  vaultCheckpoint,
  type VaultManifest,
} from '../src/index.js';
import { forEachCase } from './fuzz.js';

const KEY = new Uint8Array(32).fill(3);
const OTHER_KEY = new Uint8Array(32).fill(4);
const ID_A = '0f8fad5b-d9cb-469f-a165-70867728950e';
const ID_B = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

const manifest = (items: Record<string, number>, version = 7): VaultManifest => ({
  version,
  items,
  updatedAt: '2026-01-01T00:00:00.000Z',
  updatedBy: 'web',
});

/** Bits that differ between two base32 fingerprints. */
function bitDistance(a: string, b: string): number {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    let x = alphabet.indexOf(a[i]!) ^ alphabet.indexOf(b[i]!);
    while (x) {
      distance += x & 1;
      x >>= 1;
    }
  }
  return distance;
}

describe('vault checkpoint', () => {
  it('is the version plus a 16-character base32 fingerprint, stable for the same vault', async () => {
    const a = await vaultCheckpoint(manifest({ [ID_A]: 1, [ID_B]: 3 }), KEY);
    expect(a.version).toBe(7);
    expect(a.fingerprint).toMatch(/^[A-Z2-7]{16}$/);
    // Item order and the timestamp/client don't matter; the ids and revisions do.
    const reordered = await vaultCheckpoint(
      { ...manifest({ [ID_B]: 3, [ID_A]: 1 }), updatedAt: 'later', updatedBy: 'extension' },
      KEY,
    );
    expect(reordered).toEqual(a);
  });

  it('changes with any revision, item, or the version', async () => {
    const base = await vaultCheckpoint(manifest({ [ID_A]: 1, [ID_B]: 3 }), KEY);
    const variants = [
      manifest({ [ID_A]: 2, [ID_B]: 3 }),
      manifest({ [ID_A]: 1 }),
      manifest({ [ID_A]: 1, [ID_B]: 3, [`${ID_B.slice(0, -1)}8`]: 1 }),
      manifest({ [ID_A]: 1, [ID_B]: 3 }, 8),
    ];
    for (const variant of variants) {
      expect((await vaultCheckpoint(variant, KEY)).fingerprint).not.toBe(base.fingerprint);
    }
  });

  describe('reveals nothing about item ids', () => {
    it('depends on the vault key: the same vault under another key looks unrelated', async () => {
      const items = { [ID_A]: 1, [ID_B]: 3 };
      const mine = await vaultCheckpoint(manifest(items), KEY);
      const theirs = await vaultCheckpoint(manifest(items), OTHER_KEY);
      expect(theirs.fingerprint).not.toBe(mine.fingerprint);
      // About half the 80 bits differ, as for unrelated values.
      expect(bitDistance(mine.fingerprint, theirs.fingerprint)).toBeGreaterThan(20);
    });

    it('contains no part of any item id, in any encoding', async () => {
      await forEachCase(
        'checkpoint/ids',
        async (rng) => {
          const ids = Array.from({ length: 1 + rng.int(5) }, () => crypto.randomUUID());
          const { fingerprint } = await vaultCheckpoint(
            manifest(Object.fromEntries(ids.map((id) => [id, 1 + rng.int(9)]))),
            KEY,
          );
          for (const id of ids) {
            const hex = id.replace(/-/g, '').toUpperCase();
            const encodings = [hex, Buffer.from(hex, 'hex').toString('base64').toUpperCase()];
            for (const encoding of encodings) {
              for (let i = 0; i + 6 <= encoding.length; i++) {
                expect(fingerprint).not.toContain(encoding.slice(i, i + 6));
              }
            }
          }
        },
        100,
      );
    });

    it('a one-character change in an id changes about half the fingerprint', async () => {
      let total = 0;
      const runs = 50;
      await forEachCase(
        'checkpoint/avalanche',
        async (rng) => {
          const id = crypto.randomUUID();
          const at = rng.int(8);
          const flipped = `${id.slice(0, at)}${id[at] === 'a' ? 'b' : 'a'}${id.slice(at + 1)}`;
          const a = await vaultCheckpoint(manifest({ [id]: 1 }), KEY);
          const b = await vaultCheckpoint(manifest({ [flipped]: 1 }), KEY);
          total += bitDistance(a.fingerprint, b.fingerprint);
        },
        runs,
      );
      const average = total / runs;
      expect(average).toBeGreaterThan(30);
      expect(average).toBeLessThan(50);
    });
  });

  it('formats and parses, forgiving spaces, dashes and case', async () => {
    const checkpoint = await vaultCheckpoint(manifest({ [ID_A]: 1 }), KEY);
    const text = formatCheckpoint(checkpoint);
    expect(text).toMatch(/^7 · [A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/);
    expect(parseCheckpoint(text)).toEqual(checkpoint);
    const loose = `  v7  ${checkpoint.fingerprint.toLowerCase().replace(/(.{4})/g, '$1 ')} `;
    expect(parseCheckpoint(loose)).toEqual(checkpoint);
    for (const bad of [
      '',
      '7',
      'ABCD-EFGH-IJKL-MNOP',
      '7 · ABCD-EFGH',
      '0 · AAAAAAAAAAAAAAAA',
      '7 · AAAA1AAAAAAAAAAA',
    ]) {
      expect(() => parseCheckpoint(bad), bad).toThrow(CryptoInputError);
    }
  });

  it('compares: match, mismatch, rollback, or an older checkpoint', async () => {
    const current = await vaultCheckpoint(manifest({ [ID_A]: 2 }, 7), KEY);
    const forked = await vaultCheckpoint(manifest({ [ID_A]: 3 }, 7), KEY);
    expect(await compareCheckpoints(current, { ...current })).toBe('match');
    expect(await compareCheckpoints(current, forked)).toBe('mismatch');
    expect(
      await compareCheckpoints(current, { version: 9, fingerprint: current.fingerprint }),
    ).toBe('rollback');
    expect(await compareCheckpoints(current, { version: 3, fingerprint: forked.fingerprint })).toBe(
      'older-checkpoint',
    );
  });

  it('needs a real manifest version and a 32-byte key', async () => {
    await expect(vaultCheckpoint(manifest({}, 0), KEY)).rejects.toThrow(CryptoInputError);
    await expect(vaultCheckpoint(manifest({}), KEY.slice(1))).rejects.toThrow(CryptoInputError);
  });
});
