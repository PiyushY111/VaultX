import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  checkAgainstManifest,
  decryptManifest,
  encryptItem,
  encryptManifest,
  generateVaultKey,
  nextManifest,
  type VaultManifest,
} from '../src/index.js';
import { fromHex, sequence } from './helpers.js';

const VAULT_KEY = sequence(32).map((b) => b ^ 0xa0);
const ID = '6f1c2b1e-3d4a-4b5c-8d6e-7f8091a2b3c4';
const MANIFEST: VaultManifest = {
  version: 3,
  items: { [ID]: 7 },
  updatedAt: '2026-01-01T00:00:00.000Z',
  updatedBy: 'web',
};
// Computed independently (Node's OpenSSL ChaCha20-Poly1305 + a separate
// HChaCha20) over the exact JSON the client writes, with nonce 30 31 .. 47 and
// AAD "password-manager:v1:manifest\0" + "3".
const MANIFEST_CIPHERTEXT =
  '9cdbe856851254991af8aee9d01a13eb481c91d3142c848226e5deec965b86ab964264690dab9cb1448a5b22c6b06135d8169755842eb0cfb02502771830d965f6cd4fd80b1dc1a20e429526d3d5b28329b2835947b4ca9a42ea712bc44b286b6b74cefcd1453fe6720b0d95d78be8bbecda2699d1ab4e8c2586ced71833f3f464584819e76a57c90c443aab175f5e26b9';
const MANIFEST_NONCE = sequence(24, 0x30);

describe('encryptManifest / decryptManifest', () => {
  it('known-answer: decrypts the reference ciphertext', async () => {
    expect(
      await decryptManifest(fromHex(MANIFEST_CIPHERTEXT), MANIFEST_NONCE, VAULT_KEY, 3),
    ).toEqual(MANIFEST);
  });

  it('round-trips', async () => {
    const key = await generateVaultKey();
    const { ciphertext, nonce } = await encryptManifest(MANIFEST, key);
    expect(await decryptManifest(ciphertext, nonce, key, 3)).toEqual(MANIFEST);
  });

  it.each([2, 4])('rejects a manifest presented as version %i', async (version) => {
    await expect(
      decryptManifest(fromHex(MANIFEST_CIPHERTEXT), MANIFEST_NONCE, VAULT_KEY, version),
    ).rejects.toThrow(DecryptionError);
  });

  it('rejects a wrong key, a flipped bit, and an item ciphertext', async () => {
    const ciphertext = fromHex(MANIFEST_CIPHERTEXT);
    await expect(
      decryptManifest(ciphertext, MANIFEST_NONCE, await generateVaultKey(), 3),
    ).rejects.toThrow(DecryptionError);
    const flipped = ciphertext.slice();
    flipped[10] = flipped[10]! ^ 1;
    await expect(decryptManifest(flipped, MANIFEST_NONCE, VAULT_KEY, 3)).rejects.toThrow(
      DecryptionError,
    );
    const item = await encryptItem('{}', VAULT_KEY, { itemId: ID, revision: 3 });
    await expect(decryptManifest(item.ciphertext, item.nonce, VAULT_KEY, 3)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('refuses malformed manifests', async () => {
    for (const bad of [
      { ...MANIFEST, version: 0 },
      { ...MANIFEST, items: { [ID]: -1 } },
      { ...MANIFEST, items: [] },
      { ...MANIFEST, updatedAt: 5 },
    ]) {
      await expect(encryptManifest(bad as never, VAULT_KEY)).rejects.toThrow(CryptoInputError);
    }
  });
});

describe('checkAgainstManifest', () => {
  const manifest = { ...MANIFEST, items: { a: 1, b: 2, c: 3 } };

  it('is clean when the server returns exactly the listed items', () => {
    expect(
      checkAgainstManifest(manifest, [
        { id: 'a', revision: 1 },
        { id: 'b', revision: 2 },
        { id: 'c', revision: 3 },
      ]),
    ).toEqual({ missing: [], unexpected: [], mismatched: [] });
  });

  it('reports hidden, extra and rolled-back items', () => {
    expect(
      checkAgainstManifest(manifest, [
        { id: 'a', revision: 1 },
        { id: 'b', revision: 1 },
        { id: 'z', revision: 1 },
      ]),
    ).toEqual({ missing: ['c'], unexpected: ['z'], mismatched: ['b'] });
  });
});

describe('nextManifest', () => {
  const now = new Date('2026-02-03T04:05:06.000Z');

  it('starts at version 1', () => {
    expect(nextManifest(null, { set: [{ id: 'a', revision: 1 }] }, 'web', now)).toEqual({
      version: 1,
      items: { a: 1 },
      updatedAt: now.toISOString(),
      updatedBy: 'web',
    });
  });

  it('applies sets and removals at the next version, keeping everything else', () => {
    const current = { ...MANIFEST, items: { a: 1, b: 2 } };
    expect(
      nextManifest(current, { set: [{ id: 'a', revision: 2 }], remove: ['b'] }, 'extension', now),
    ).toMatchObject({ version: 4, items: { a: 2 }, updatedBy: 'extension' });
    expect(current.items).toEqual({ a: 1, b: 2 });
  });

  it('can replace the whole list', () => {
    const current = { ...MANIFEST, items: { a: 1 } };
    expect(
      nextManifest(current, { set: [{ id: 'b', revision: 1 }], replaceAll: true }, 'web', now)
        .items,
    ).toEqual({ b: 1 });
  });
});
