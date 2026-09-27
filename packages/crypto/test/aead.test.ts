import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  decryptItem,
  decryptVaultKey,
  deriveKeys,
  encryptItem,
  encryptVaultKey,
  generateVaultKey,
} from '../src/index.js';
import { fixNextRandomBytes, fromHex, sequence, sodium, toHex } from './helpers.js';

// Fixed inputs. Expected ciphertexts were computed independently with Node's
// OpenSSL chacha20-poly1305 plus a separate HChaCha20 implementation (the
// XChaCha20 construction), not with libsodium.
const VAULT_KEY = sequence(32).map((b) => b ^ 0xa0);
const ITEM_NONCE = sequence(24, 0x10);
const ITEM_JSON = '{"name":"example.com","username":"alice","password":"hunter2"}';
const ITEM_ID = '6f1c2b1e-3d4a-4b5c-8d6e-7f8091a2b3c4';
const BINDING = { itemId: ITEM_ID, revision: 7 };
// AAD "password-manager:v2:item\0<ITEM_ID>\0" + "7".
const ITEM_CIPHERTEXT =
  '188cfcf69ef350da572012d10107485efa999495d2c99dd55ff106c7d3b056ded4e7e0383af73411e90c71d0742bdb22d5afc753b6426ee7a19f7798780295ec158636959e1d3f7e65d6154cf85b';
// The same item saved before binding existed (AAD "password-manager:v1:item").
const LEGACY_ITEM_CIPHERTEXT =
  '188cfcf69ef350da572012d10107485efa999495d2c99dd55ff106c7d3b056ded4e7e0383af73411e90c71d0742bdb22d5afc753b6426ee7a19f779878029b41a46521f4cb773d716f4b6aa5d8e8';
const LEGACY = { itemId: ITEM_ID, revision: 0 };

// stretchedMasterKey for masterKey = 00 01 .. 1f (see keys.test.ts).
const STRETCHED_MASTER_KEY = fromHex(
  '1bb24421f52d0377ff43ca8a2ba69fb742a1d2fe8cab077c48ec25aeeb555b58',
);
const VAULT_KEY_NONCE = sequence(24, 0x40);
const VAULT_KEY_CIPHERTEXT =
  '625a6679d4ebecdaeb9cb8741a25a13f2b79d6c6381eaa4df4eef9a2045179bdc22436a6e9ce439fb28d800aa364b4f6';

afterEach(() => {
  vi.restoreAllMocks();
});

/** Every single-bit flip of `bytes`, one at a time. */
function* bitFlips(bytes: Uint8Array): Generator<Uint8Array> {
  for (let i = 0; i < bytes.length; i++) {
    for (let bit = 0; bit < 8; bit++) {
      const copy = Uint8Array.from(bytes);
      copy[i] = copy[i]! ^ (1 << bit);
      yield copy;
    }
  }
}

describe('XChaCha20-Poly1305 primitive', () => {
  it('matches draft-irtf-cfrg-xchacha-03 test vector A.3.1', async () => {
    await sodium.ready;
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
      fromHex('50515253c0c1c2c3c4c5c6c7'),
      null,
      fromHex('404142434445464748494a4b4c4d4e4f5051525354555657'),
      fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
    );
    expect(toHex(ciphertext)).toBe(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e' +
        'c0875924c1c7987947deafd8780acf49',
    );
  });
});

describe('generateVaultKey', () => {
  it('returns 32 bytes', async () => {
    expect(await generateVaultKey()).toHaveLength(32);
  });

  it('returns a different key on every call', async () => {
    const keys = await Promise.all(Array.from({ length: 100 }, () => generateVaultKey()));
    expect(new Set(keys.map(toHex)).size).toBe(100);
  });

  it("uses libsodium's CSPRNG, never Math.random", async () => {
    const mathRandom = vi.spyOn(Math, 'random');
    const keygen = vi.spyOn(sodium, 'crypto_aead_xchacha20poly1305_ietf_keygen');
    await generateVaultKey();
    expect(keygen).toHaveBeenCalledOnce();
    expect(mathRandom).not.toHaveBeenCalled();
  });
});

describe('encryptVaultKey / decryptVaultKey', () => {
  it('known-answer: fixed key + fixed nonce produce the reference ciphertext', async () => {
    await fixNextRandomBytes(VAULT_KEY_NONCE);
    const { ciphertext, nonce } = await encryptVaultKey(VAULT_KEY, STRETCHED_MASTER_KEY);
    expect(toHex(nonce)).toBe(toHex(VAULT_KEY_NONCE));
    expect(toHex(ciphertext)).toBe(VAULT_KEY_CIPHERTEXT);
  });

  it('known-answer: decrypts the reference ciphertext', async () => {
    const vaultKey = await decryptVaultKey(
      fromHex(VAULT_KEY_CIPHERTEXT),
      VAULT_KEY_NONCE,
      STRETCHED_MASTER_KEY,
    );
    expect(vaultKey).toEqual(VAULT_KEY);
  });

  it('round-trips a generated vault key', async () => {
    const vaultKey = await generateVaultKey();
    const { ciphertext, nonce } = await encryptVaultKey(vaultKey, STRETCHED_MASTER_KEY);
    expect(ciphertext).toHaveLength(32 + 16);
    expect(await decryptVaultKey(ciphertext, nonce, STRETCHED_MASTER_KEY)).toEqual(vaultKey);
  });

  it('uses a fresh nonce for every call', async () => {
    const a = await encryptVaultKey(VAULT_KEY, STRETCHED_MASTER_KEY);
    const b = await encryptVaultKey(VAULT_KEY, STRETCHED_MASTER_KEY);
    expect(a.nonce).toHaveLength(24);
    expect(b.nonce).not.toEqual(a.nonce);
    expect(b.ciphertext).not.toEqual(a.ciphertext);
  });

  describe('rejects', () => {
    it('a wrong stretched master key', async () => {
      const { ciphertext, nonce } = await encryptVaultKey(VAULT_KEY, STRETCHED_MASTER_KEY);
      await expect(decryptVaultKey(ciphertext, nonce, await generateVaultKey())).rejects.toThrow(
        DecryptionError,
      );
    });

    it('the authHash — it must not be able to decrypt the vault key', async () => {
      const { stretchedMasterKey, authHash } = await deriveKeys(sequence(32));
      const { ciphertext, nonce } = await encryptVaultKey(VAULT_KEY, stretchedMasterKey);
      await expect(decryptVaultKey(ciphertext, nonce, authHash)).rejects.toThrow(DecryptionError);
    });

    it('every single-bit flip of the ciphertext', async () => {
      const ciphertext = fromHex(VAULT_KEY_CIPHERTEXT);
      for (const tampered of bitFlips(ciphertext)) {
        await expect(
          decryptVaultKey(tampered, VAULT_KEY_NONCE, STRETCHED_MASTER_KEY),
        ).rejects.toThrow(DecryptionError);
      }
    });

    it('every single-bit flip of the nonce', async () => {
      const ciphertext = fromHex(VAULT_KEY_CIPHERTEXT);
      for (const tampered of bitFlips(VAULT_KEY_NONCE)) {
        await expect(decryptVaultKey(ciphertext, tampered, STRETCHED_MASTER_KEY)).rejects.toThrow(
          DecryptionError,
        );
      }
    });

    it('a truncated or empty ciphertext', async () => {
      const ciphertext = fromHex(VAULT_KEY_CIPHERTEXT);
      for (const length of [0, 1, 15, 16, 47]) {
        await expect(
          decryptVaultKey(ciphertext.subarray(0, length), VAULT_KEY_NONCE, STRETCHED_MASTER_KEY),
        ).rejects.toThrow(DecryptionError);
      }
    });

    it('an item ciphertext presented as a vault key, even under the same key', async () => {
      const { ciphertext, nonce } = await encryptItem(ITEM_JSON, STRETCHED_MASTER_KEY, BINDING);
      await expect(decryptVaultKey(ciphertext, nonce, STRETCHED_MASTER_KEY)).rejects.toThrow(
        DecryptionError,
      );
    });

    it('malformed keys and nonces', async () => {
      await expect(encryptVaultKey(new Uint8Array(31), STRETCHED_MASTER_KEY)).rejects.toThrow(
        CryptoInputError,
      );
      await expect(encryptVaultKey(VAULT_KEY, new Uint8Array(16))).rejects.toThrow(
        CryptoInputError,
      );
      const ciphertext = fromHex(VAULT_KEY_CIPHERTEXT);
      await expect(
        decryptVaultKey(ciphertext, new Uint8Array(12), STRETCHED_MASTER_KEY),
      ).rejects.toThrow(CryptoInputError);
      await expect(
        decryptVaultKey(ciphertext, VAULT_KEY_NONCE, new Uint8Array(33)),
      ).rejects.toThrow(CryptoInputError);
    });
  });
});

describe('encryptItem / decryptItem', () => {
  it('known-answer: fixed key + fixed nonce produce the reference ciphertext', async () => {
    await fixNextRandomBytes(ITEM_NONCE);
    const { ciphertext, nonce } = await encryptItem(ITEM_JSON, VAULT_KEY, BINDING);
    expect(toHex(nonce)).toBe(toHex(ITEM_NONCE));
    expect(toHex(ciphertext)).toBe(ITEM_CIPHERTEXT);
  });

  it('known-answer: decrypts the reference ciphertext', async () => {
    expect(await decryptItem(fromHex(ITEM_CIPHERTEXT), ITEM_NONCE, VAULT_KEY, BINDING)).toBe(
      ITEM_JSON,
    );
  });

  it('known-answer: decrypts an item saved before binding existed as revision 0', async () => {
    expect(await decryptItem(fromHex(LEGACY_ITEM_CIPHERTEXT), ITEM_NONCE, VAULT_KEY, LEGACY)).toBe(
      ITEM_JSON,
    );
  });

  it('never writes revision 0, so new saves are always bound', async () => {
    await expect(encryptItem(ITEM_JSON, VAULT_KEY, LEGACY)).rejects.toThrow(CryptoInputError);
  });

  it.each([
    ['a typical item', ITEM_JSON],
    ['an empty string', ''],
    ['non-ASCII text', '{"note":"pässwörd 🔐 密码"}'],
    ['a large item', JSON.stringify({ notes: 'x'.repeat(1_000_000) })],
  ])('round-trips %s', async (_, plaintext) => {
    const { ciphertext, nonce } = await encryptItem(plaintext, VAULT_KEY, BINDING);
    expect(await decryptItem(ciphertext, nonce, VAULT_KEY, BINDING)).toBe(plaintext);
  });

  it('uses a fresh nonce for every call, so equal plaintexts give different ciphertexts', async () => {
    const results = await Promise.all(
      Array.from({ length: 100 }, () => encryptItem(ITEM_JSON, VAULT_KEY, BINDING)),
    );
    expect(new Set(results.map((r) => toHex(r.nonce))).size).toBe(100);
    expect(new Set(results.map((r) => toHex(r.ciphertext))).size).toBe(100);
    for (const { nonce } of results) {
      expect(nonce).toHaveLength(24);
    }
  });

  it('does not leak plaintext into the ciphertext', async () => {
    const { ciphertext } = await encryptItem(ITEM_JSON, VAULT_KEY, BINDING);
    expect(Buffer.from(ciphertext).includes('hunter2')).toBe(false);
  });

  describe('rejects', () => {
    it('a wrong vault key', async () => {
      await expect(
        decryptItem(fromHex(ITEM_CIPHERTEXT), ITEM_NONCE, await generateVaultKey(), BINDING),
      ).rejects.toThrow(DecryptionError);
    });

    it('every single-bit flip of the ciphertext', async () => {
      const ciphertext = fromHex(ITEM_CIPHERTEXT);
      for (const tampered of bitFlips(ciphertext)) {
        await expect(decryptItem(tampered, ITEM_NONCE, VAULT_KEY, BINDING)).rejects.toThrow(
          DecryptionError,
        );
      }
    });

    it('every single-bit flip of the nonce', async () => {
      const ciphertext = fromHex(ITEM_CIPHERTEXT);
      for (const tampered of bitFlips(ITEM_NONCE)) {
        await expect(decryptItem(ciphertext, tampered, VAULT_KEY, BINDING)).rejects.toThrow(
          DecryptionError,
        );
      }
    });

    it('a truncated, extended, or empty ciphertext', async () => {
      const ciphertext = fromHex(ITEM_CIPHERTEXT);
      const extended = new Uint8Array(ciphertext.length + 1);
      extended.set(ciphertext);
      for (const tampered of [
        ciphertext.subarray(0, 0),
        ciphertext.subarray(0, 16),
        ciphertext.subarray(0, -1),
        extended,
      ]) {
        await expect(decryptItem(tampered, ITEM_NONCE, VAULT_KEY, BINDING)).rejects.toThrow(
          DecryptionError,
        );
      }
    });

    it('a ciphertext paired with another item’s nonce', async () => {
      const a = await encryptItem(ITEM_JSON, VAULT_KEY, BINDING);
      const b = await encryptItem(ITEM_JSON, VAULT_KEY, BINDING);
      await expect(decryptItem(a.ciphertext, b.nonce, VAULT_KEY, BINDING)).rejects.toThrow(
        DecryptionError,
      );
    });

    it('a ciphertext presented as another item', async () => {
      const other = { ...BINDING, itemId: '0b7f7c1a-2e3d-4c5b-9a69-788796a5b4c3' };
      await expect(
        decryptItem(fromHex(ITEM_CIPHERTEXT), ITEM_NONCE, VAULT_KEY, other),
      ).rejects.toThrow(DecryptionError);
    });

    it.each([
      ['an older', 6],
      ['a newer', 8],
      ['the legacy', 0],
    ])('a ciphertext presented as %s revision', async (_, revision) => {
      await expect(
        decryptItem(fromHex(ITEM_CIPHERTEXT), ITEM_NONCE, VAULT_KEY, { ...BINDING, revision }),
      ).rejects.toThrow(DecryptionError);
    });

    it('a legacy ciphertext presented as a bound revision', async () => {
      await expect(
        decryptItem(fromHex(LEGACY_ITEM_CIPHERTEXT), ITEM_NONCE, VAULT_KEY, {
          ...BINDING,
          revision: 1,
        }),
      ).rejects.toThrow(DecryptionError);
    });

    it('a wrapped vault key presented as an item, even under the same key', async () => {
      const { ciphertext, nonce } = await encryptVaultKey(VAULT_KEY, VAULT_KEY);
      await expect(decryptItem(ciphertext, nonce, VAULT_KEY, BINDING)).rejects.toThrow(
        DecryptionError,
      );
    });

    it('malformed inputs', async () => {
      await expect(encryptItem(ITEM_JSON, new Uint8Array(16), BINDING)).rejects.toThrow(
        CryptoInputError,
      );
      await expect(encryptItem({} as unknown as string, VAULT_KEY, BINDING)).rejects.toThrow(
        CryptoInputError,
      );
      const ciphertext = fromHex(ITEM_CIPHERTEXT);
      await expect(decryptItem(ciphertext, new Uint8Array(23), VAULT_KEY, BINDING)).rejects.toThrow(
        CryptoInputError,
      );
      await expect(decryptItem(ciphertext, ITEM_NONCE, new Uint8Array(0), BINDING)).rejects.toThrow(
        CryptoInputError,
      );
      for (const binding of [
        { itemId: 'not-a-uuid', revision: 1 },
        { itemId: ITEM_ID.toUpperCase(), revision: 1 },
        { itemId: ITEM_ID, revision: -1 },
        { itemId: ITEM_ID, revision: 1.5 },
        null,
      ]) {
        await expect(
          encryptItem(ITEM_JSON, VAULT_KEY, binding as never),
          JSON.stringify(binding),
        ).rejects.toThrow(CryptoInputError);
        await expect(
          decryptItem(ciphertext, ITEM_NONCE, VAULT_KEY, binding as never),
        ).rejects.toThrow(CryptoInputError);
      }
    });
  });
});
