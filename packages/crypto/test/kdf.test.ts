import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DEFAULT_KDF_PARAMS,
  MIN_KDF_PARAMS,
  deriveMasterKey,
  generateSalt,
  type KdfParams,
} from '../src/index.js';
import { fromHex, toHex } from './helpers.js';

// Expected values were computed independently with Node's OpenSSL
// crypto.argon2Sync('argon2id', ...), not with this module.
const PASSWORD = 'correct horse battery staple';
const SALT = fromHex('000102030405060708090a0b0c0d0e0f');

describe('deriveMasterKey', () => {
  describe('known-answer', () => {
    it('matches the reference output at minimum params (m=19456 KiB, t=2, p=1)', async () => {
      const key = await deriveMasterKey(PASSWORD, SALT, MIN_KDF_PARAMS);
      expect(toHex(key)).toBe('818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085');
    });

    it('matches the reference output at default params (m=65536 KiB, t=3, p=1)', async () => {
      const key = await deriveMasterKey(PASSWORD, SALT, DEFAULT_KDF_PARAMS);
      expect(toHex(key)).toBe('0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e');
    });

    it('NFC-normalizes the password so composed and decomposed forms agree', async () => {
      const composed = await deriveMasterKey('passwörd', SALT, MIN_KDF_PARAMS);
      const decomposed = await deriveMasterKey('passwörd', SALT, MIN_KDF_PARAMS);
      expect(toHex(composed)).toBe(
        '301cf18ef93f5a5b4b86ef5bc8116bf994c0581c6136cacd6cdd1b3aaa6a7e7d',
      );
      expect(decomposed).toEqual(composed);
    });
  });

  it('returns a 32-byte key and is deterministic', async () => {
    const a = await deriveMasterKey(PASSWORD, SALT, MIN_KDF_PARAMS);
    const b = await deriveMasterKey(PASSWORD, SALT, MIN_KDF_PARAMS);
    expect(a).toHaveLength(32);
    expect(b).toEqual(a);
  });

  it('produces different keys for a different password, salt, or params', async () => {
    const base = await deriveMasterKey(PASSWORD, SALT, MIN_KDF_PARAMS);
    const otherPassword = await deriveMasterKey(PASSWORD + '!', SALT, MIN_KDF_PARAMS);
    const otherSalt = await deriveMasterKey(PASSWORD, fromHex('ff'.repeat(16)), MIN_KDF_PARAMS);
    const otherParams = await deriveMasterKey(PASSWORD, SALT, { ...MIN_KDF_PARAMS, iterations: 3 });
    for (const other of [otherPassword, otherSalt, otherParams]) {
      expect(other).not.toEqual(base);
    }
  });

  describe('input validation', () => {
    it('rejects an empty password', async () => {
      await expect(deriveMasterKey('', SALT, MIN_KDF_PARAMS)).rejects.toThrow(CryptoInputError);
    });

    it.each([0, 15, 17, 32])('rejects a %i-byte salt', async (length) => {
      await expect(
        deriveMasterKey(PASSWORD, new Uint8Array(length), MIN_KDF_PARAMS),
      ).rejects.toThrow(CryptoInputError);
    });

    const badParams: [string, KdfParams][] = [
      [
        'memoryCost below minimum',
        { ...MIN_KDF_PARAMS, memoryCost: MIN_KDF_PARAMS.memoryCost - 1 },
      ],
      ['memoryCost above maximum', { ...MIN_KDF_PARAMS, memoryCost: 2 * 1024 * 1024 }],
      ['iterations below minimum', { ...MIN_KDF_PARAMS, iterations: 1 }],
      ['parallelism other than 1', { ...MIN_KDF_PARAMS, parallelism: 4 }],
      ['non-integer memoryCost', { ...MIN_KDF_PARAMS, memoryCost: 20000.5 }],
      ['NaN iterations', { ...MIN_KDF_PARAMS, iterations: Number.NaN }],
    ];
    it.each(badParams)('rejects %s', async (_, params) => {
      await expect(deriveMasterKey(PASSWORD, SALT, params)).rejects.toThrow(CryptoInputError);
    });
  });
});

describe('generateSalt', () => {
  it('returns 16 random bytes that differ between calls', async () => {
    const a = await generateSalt();
    const b = await generateSalt();
    expect(a).toHaveLength(16);
    expect(b).not.toEqual(a);
  });
});
