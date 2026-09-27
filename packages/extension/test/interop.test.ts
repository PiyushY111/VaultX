import { generateVaultKey } from '@password-manager/crypto';
import { describe, expect, it } from 'vitest';
import {
  decryptVaultItems as webDecrypt,
  encryptNewItem as webEncryptNew,
  parseItem as webParse,
  serializeItem as webSerialize,
} from '../../web/src/vault/items';
import {
  decryptVaultItems,
  encryptVaultItem,
  parseItem,
  serializeItem,
} from '../src/background/items';

// Items saved by the extension must open in the web vault and vice versa.
describe('item format is shared with packages/web', () => {
  const data = { site: 'github.com', username: 'octocat', password: 'p@ss "x"', notes: 'n\nm' };

  it('serializes identically', () => {
    expect(serializeItem(data)).toBe(webSerialize(data));
  });

  it('round-trips across packages', () => {
    expect(webParse(serializeItem(data))).toEqual(data);
    expect(parseItem(webSerialize(data))).toEqual(data);
  });

  it('decrypts each other’s ciphertexts, bound to the same id and revision', async () => {
    const key = await generateVaultKey();
    const stamps = { created_at: '', updated_at: '' };
    const fromWeb = { ...(await webEncryptNew(data, key)), ...stamps };
    const fromExtension = {
      ...(await encryptVaultItem(data, key, crypto.randomUUID(), 3)),
      ...stamps,
    };
    expect((await decryptVaultItems([fromWeb], key)).items).toMatchObject([data]);
    expect((await webDecrypt([fromExtension], key)).items).toMatchObject([
      { ...data, revision: 3 },
    ]);
  });
});
