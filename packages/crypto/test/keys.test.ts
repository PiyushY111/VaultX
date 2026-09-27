import { describe, expect, it } from 'vitest';
import { CryptoInputError, deriveKeys } from '../src/index.js';
import { sequence, toHex } from './helpers.js';

// Expected values computed independently with Node's OpenSSL
// crypto.hkdfSync('sha256', masterKey, <empty salt>, info, 32).
const MASTER_KEY = sequence(32);

describe('deriveKeys', () => {
  it('matches the HKDF-SHA256 reference output', async () => {
    const { stretchedMasterKey, authHash } = await deriveKeys(MASTER_KEY);
    expect(toHex(stretchedMasterKey)).toBe(
      '1bb24421f52d0377ff43ca8a2ba69fb742a1d2fe8cab077c48ec25aeeb555b58',
    );
    expect(toHex(authHash)).toBe(
      'f09f944a0a5e40fb671cf3e07d1659dafa6188529c5890cbccd75345087c81f0',
    );
  });

  it('returns two distinct 32-byte keys, neither equal to the master key', async () => {
    const { stretchedMasterKey, authHash } = await deriveKeys(MASTER_KEY);
    expect(stretchedMasterKey).toHaveLength(32);
    expect(authHash).toHaveLength(32);
    expect(authHash).not.toEqual(stretchedMasterKey);
    expect(stretchedMasterKey).not.toEqual(MASTER_KEY);
    expect(authHash).not.toEqual(MASTER_KEY);
  });

  it('is deterministic and sensitive to the master key', async () => {
    const a = await deriveKeys(MASTER_KEY);
    const b = await deriveKeys(MASTER_KEY);
    const other = await deriveKeys(sequence(32, 1));
    expect(b).toEqual(a);
    expect(other.stretchedMasterKey).not.toEqual(a.stretchedMasterKey);
    expect(other.authHash).not.toEqual(a.authHash);
  });

  it('does not mutate the master key', async () => {
    const masterKey = sequence(32);
    await deriveKeys(masterKey);
    expect(masterKey).toEqual(sequence(32));
  });

  it.each([0, 16, 31, 33, 64])('rejects a %i-byte master key', async (length) => {
    await expect(deriveKeys(new Uint8Array(length))).rejects.toThrow(CryptoInputError);
  });
});
