import { generateVaultKey } from '@password-manager/crypto';
import * as format from '@password-manager/item-format';
import { describe, expect, it } from 'vitest';
import * as web from '../../web/src/vault/items';
import * as extension from '../src/background/items';

// Items saved by the extension must open in the web vault and vice versa.
describe('item format is shared with packages/web', () => {
  const data = { site: 'github.com', username: 'octocat', password: 'p@ss "x"', notes: 'n\nm' };
  const stamps = { created_at: '', updated_at: '' };

  it('comes from one implementation, @password-manager/item-format', () => {
    for (const name of [
      'parseItem',
      'serializeItem',
      'normalizeTags',
      'isLogin',
      'withPasswordHistory',
      'ITEM_TYPES',
    ] as const) {
      expect(web[name], name).toBe(format[name]);
      expect(extension[name], name).toBe(format[name]);
    }
    expect(extension.MAX_PASSWORD_HISTORY).toBe(web.MAX_PASSWORD_HISTORY);
  });

  it('decrypts each other’s ciphertexts, bound to the same id and revision', async () => {
    const key = await generateVaultKey();
    const fromWeb = { ...(await web.encryptNewItem(data, key)), ...stamps };
    const fromExtension = {
      ...(await extension.encryptVaultItem(data, key, crypto.randomUUID(), 3)),
      ...stamps,
    };
    expect((await extension.decryptVaultItems([fromWeb], key)).items).toMatchObject([data]);
    expect((await web.decryptVaultItems([fromExtension], key)).items).toMatchObject([
      { ...data, revision: 3 },
    ]);
  });

  it('agrees on items in the trash and in folders', async () => {
    const key = await generateVaultKey();
    const trashed = {
      ...data,
      deletedAt: '2026-10-01T00:00:00.000Z',
      folder: 'Work/Servers',
      match: 'exact' as const,
    };
    const fromWeb = { ...(await web.encryptNewItem(trashed, key)), ...stamps };
    const [inExtension] = (await extension.decryptVaultItems([fromWeb], key)).items;
    expect(inExtension).toMatchObject(trashed);
    expect(extension.isTrashed(inExtension!)).toBe(true);
  });

  it('keeps fields from newer versions in both directions', async () => {
    const key = await generateVaultKey();
    const withExtra = { ...data, extra: { futureLabel: 'Work', futureMode: 'exact' } };
    const fromWeb = { ...(await web.encryptNewItem(withExtra, key)), ...stamps };
    const [inExtension] = (await extension.decryptVaultItems([fromWeb], key)).items;
    expect(inExtension!.extra).toEqual(withExtra.extra);

    const back = {
      ...(await extension.encryptVaultItem(inExtension!, key, fromWeb.id, 2)),
      ...stamps,
    };
    expect((await web.decryptVaultItems([back], key)).items).toMatchObject([withExtra]);
  });
});
