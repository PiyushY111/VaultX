import sodium from 'libsodium-wrappers-sumo';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  decryptManifest,
  encryptManifest,
  parseCheckpoint,
  parseTotp,
  type VaultManifest,
} from '../src/index.js';
import { AAD_MANIFEST } from '../src/constants.js';
import { expectTyped, forEachCase, mutate, type Rng } from './fuzz.js';

/**
 * Seeded randomized tests: whatever the input, these functions return a
 * well-formed result or throw their documented error type, and quickly.
 * Reproduce a failure with the FUZZ_SEED it prints.
 */

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function otpauthLike(rng: Rng): string {
  const params = [
    rng.bool(0.8) && `secret=${rng.string(40, `${BASE32}=- abc`)}`,
    rng.bool() && `issuer=${rng.string(12)}`,
    rng.bool() && `algorithm=${rng.pick(['SHA1', 'SHA256', 'sha512', 'MD5', '', '__PROTO__'])}`,
    rng.bool() && `digits=${rng.pick(['6', '8', '7', '0', '-1', '1e3', 'x', ''])}`,
    rng.bool() && `period=${rng.pick(['30', '60', '0', '301', '1.5', 'NaN', ''])}`,
    rng.bool(0.2) && `${rng.string(6)}=${rng.string(6)}`,
  ].filter(Boolean);
  const type = rng.pick(['totp', 'TOTP', 'hotp', '', 'x']);
  const label = rng.pick(['', 'Issuer:alice', '%E2%9C%93', '%', '%zz', rng.string(10)]);
  return `${rng.pick(['otpauth://', 'OTPAUTH://', 'otpauth:', 'otpauth:///'])}${type}/${label}?${params.join('&')}`;
}

describe('parseTotp', () => {
  it('returns a valid config or throws CryptoInputError, for any input', async () => {
    await forEachCase('parseTotp', async (rng) => {
      const input = rng.pick([
        () => rng.string(60),
        () => rng.string(60, `${BASE32} -=`),
        () => otpauthLike(rng),
        () => mutate(rng, otpauthLike(rng)),
        () => mutate(rng, 'otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example'),
      ])();
      const result = await expectTyped(() => parseTotp(input), [CryptoInputError], input);
      if (result.ok) {
        const { secret, algorithm, digits, period } = result.value;
        expect(secret.length).toBeGreaterThanOrEqual(10);
        expect(['SHA-1', 'SHA-256', 'SHA-512']).toContain(algorithm);
        expect([6, 7, 8]).toContain(digits);
        expect(Number.isInteger(period) && period >= 1 && period <= 300).toBe(true);
      }
    });
  });

  it('handles very large input in linear time', async () => {
    const huge = `otpauth://totp/${'a:'.repeat(200_000)}?${'x=y&'.repeat(100_000)}secret=${'A'.repeat(100_000)}`;
    await expectTyped(() => parseTotp(huge), [CryptoInputError], 'huge otpauth', 1000);
    await expectTyped(() => parseTotp(' '.repeat(1_000_000)), [CryptoInputError], 'spaces', 1000);
  });
});

describe('decryptManifest', () => {
  const key = new Uint8Array(32).fill(7);
  const manifest: VaultManifest = {
    version: 3,
    items: { '00000000-0000-4000-8000-000000000001': 2 },
    updatedAt: '2026-01-01T00:00:00.000Z',
    updatedBy: 'test',
  };
  let valid: { ciphertext: Uint8Array; nonce: Uint8Array };

  beforeAll(async () => {
    await sodium.ready;
    valid = await encryptManifest(manifest, key);
  });

  /** An authentic ciphertext (as a key holder could write) over any plaintext. */
  const sealed = (plaintext: string, version: number) => {
    const nonce = sodium.randombytes_buf(24);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      sodium.from_string(plaintext),
      sodium.from_string(`${AAD_MANIFEST}\0${version}`),
      null,
      nonce,
      key,
    );
    return { ciphertext, nonce };
  };

  it('opens a valid manifest', async () => {
    expect(await decryptManifest(valid.ciphertext, valid.nonce, key, 3)).toEqual(manifest);
  });

  it('throws only DecryptionError for random or tampered data from the server', async () => {
    await forEachCase('decryptManifest/tampered', async (rng) => {
      const ciphertext = rng.bool(0.3) ? rng.bytes(rng.int(80)) : valid.ciphertext.slice();
      if (rng.bool(0.7) && ciphertext.length)
        ciphertext[rng.int(ciphertext.length)]! ^= 1 << rng.int(8);
      const nonce = rng.bool(0.8) ? valid.nonce.slice() : rng.bytes(rng.pick([0, 12, 23, 24, 25]));
      const version = rng.pick([3, 2, 4, 0, -1, 1.5, Number.NaN, 2 ** 53, Infinity]);
      const input = { ciphertext: [...ciphertext], nonce: [...nonce], version };
      const unchanged =
        version === 3 &&
        nonce.length === 24 &&
        sodium.memcmp(nonce, valid.nonce) &&
        ciphertext.length === valid.ciphertext.length &&
        sodium.memcmp(ciphertext, valid.ciphertext);
      const result = await expectTyped(
        () => decryptManifest(ciphertext, nonce, key, version),
        [DecryptionError],
        input,
      );
      expect(result.ok).toBe(unchanged);
    });
  });

  it('throws only DecryptionError for authentic ciphertexts over malformed plaintext', async () => {
    await forEachCase('decryptManifest/plaintext', async (rng) => {
      const good = JSON.stringify({
        v: 1,
        version: 3,
        items: manifest.items,
        updated_at: manifest.updatedAt,
        updated_by: manifest.updatedBy,
      });
      const plaintext = rng.pick([
        () => JSON.stringify(rng.json()),
        () => mutate(rng, good),
        () => rng.string(40),
        () => 'null',
        () => JSON.stringify({ ...JSON.parse(good), items: rng.json() }),
        () => JSON.stringify({ ...JSON.parse(good), updated_at: rng.json() }),
      ])();
      const { ciphertext, nonce } = sealed(plaintext, 3);
      const result = await expectTyped(
        () => decryptManifest(ciphertext, nonce, key, 3),
        [DecryptionError],
        plaintext,
      );
      if (result.ok) {
        expect(result.value.version).toBe(3);
        expect(typeof result.value.updatedAt).toBe('string');
        expect(Object.values(result.value.items).every(Number.isSafeInteger)).toBe(true);
      }
    });
  });

  it('reports a malformed key as the caller’s bug (CryptoInputError)', async () => {
    await expect(decryptManifest(valid.ciphertext, valid.nonce, key.slice(1), 3)).rejects.toThrow(
      CryptoInputError,
    );
  });
});

describe('parseCheckpoint', () => {
  it('returns a valid checkpoint or throws CryptoInputError, for any input', async () => {
    await forEachCase('parseCheckpoint', async (rng) => {
      const input = rng.pick([
        () => rng.string(40),
        () => mutate(rng, '42 · ABCD-EFGH-IJKL-MNOP'),
        () => `${rng.pick(['', 'v', ' '])}${rng.int(1e6)} ${rng.string(24, `${BASE32}- ·abc`)}`,
      ])();
      const result = await expectTyped(() => parseCheckpoint(input), [CryptoInputError], input);
      if (result.ok) {
        expect(Number.isSafeInteger(result.value.version) && result.value.version >= 1).toBe(true);
        expect(result.value.fingerprint).toMatch(/^[A-Z2-7]{16}$/);
      }
    });
    await expectTyped(
      () => parseCheckpoint(`1 ${'A-'.repeat(500_000)}`),
      [CryptoInputError],
      'long',
      1000,
    );
  });
});
