import { describe, expect, it } from 'vitest';
import {
  CryptoInputError,
  DecryptionError,
  decryptBackup,
  decryptItem,
  encryptBackup,
  encryptItem,
  generateVaultKey,
} from '../src/index.js';

const JSON_TEXT = '{"v":1,"items":[{"site":"github.com","password":"hunter2"}]}';

describe('encryptBackup / decryptBackup', () => {
  it('round-trips, with a fresh nonce each time', async () => {
    const key = await generateVaultKey();
    const a = await encryptBackup(JSON_TEXT, key);
    const b = await encryptBackup(JSON_TEXT, key);
    expect(a.nonce).not.toEqual(b.nonce);
    expect(await decryptBackup(a.ciphertext, a.nonce, key)).toBe(JSON_TEXT);
    expect(Buffer.from(a.ciphertext).includes('hunter2')).toBe(false);
  });

  it('rejects a wrong key and a damaged file', async () => {
    const key = await generateVaultKey();
    const { ciphertext, nonce } = await encryptBackup(JSON_TEXT, key);
    await expect(decryptBackup(ciphertext, nonce, await generateVaultKey())).rejects.toThrow(
      DecryptionError,
    );
    const damaged = ciphertext.slice();
    damaged[3] = damaged[3]! ^ 1;
    await expect(decryptBackup(damaged, nonce, key)).rejects.toThrow(DecryptionError);
    await expect(decryptBackup(ciphertext.subarray(0, 8), nonce, key)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('is kept apart from items: neither opens as the other', async () => {
    const key = await generateVaultKey();
    const binding = { itemId: crypto.randomUUID(), revision: 1 };
    const item = await encryptItem(JSON_TEXT, key, binding);
    await expect(decryptBackup(item.ciphertext, item.nonce, key)).rejects.toThrow(DecryptionError);
    const backup = await encryptBackup(JSON_TEXT, key);
    await expect(decryptItem(backup.ciphertext, backup.nonce, key, binding)).rejects.toThrow(
      DecryptionError,
    );
  });

  it('refuses malformed input', async () => {
    await expect(encryptBackup(JSON_TEXT, new Uint8Array(16))).rejects.toThrow(CryptoInputError);
    await expect(encryptBackup(5 as never, await generateVaultKey())).rejects.toThrow(
      CryptoInputError,
    );
  });
});
