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

  it('keeps two-factor secrets across packages', () => {
    const withTotp = { ...data, totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' };
    expect(serializeItem(withTotp)).toBe(webSerialize(withTotp));
    expect(webParse(serializeItem(withTotp))).toEqual(withTotp);
    expect(parseItem(webSerialize(withTotp))).toEqual(withTotp);
  });

  it('agrees on every optional field: type, tags, favorite, card details, history', () => {
    const full = {
      ...data,
      type: 'card' as const,
      tags: ['Work', 'travel'],
      favorite: true,
      fields: {
        cardholder: 'A. Person',
        number: '4111 1111 1111 1111',
        expiry: '12/30',
        cvv: '123',
      },
      history: [{ password: 'old-pw', changedAt: '2026-01-01T00:00:00.000Z' }],
    };
    expect(serializeItem(full)).toBe(webSerialize(full));
    expect(parseItem(webSerialize(full))).toEqual(full);
    expect(webParse(serializeItem(full))).toEqual(full);
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
