import { generateVaultKey } from '@password-manager/crypto';
import sodium from 'libsodium-wrappers-sumo';
import { describe, expect, it } from 'vitest';
import type { ItemResponse } from '../api';
import { toBase64 } from '../lib/base64';
import {
  decryptVaultItems,
  encryptNewItem,
  encryptNextRevision,
  filterItems,
  parseItem,
  serializeItem,
  type VaultItem,
} from './items';
import { createRevisionLedger } from './revisionLedger';

const item = (site: string, username = '', notes = '', password = 'pw'): VaultItem => ({
  id: site,
  revision: 1,
  site,
  username,
  password,
  notes,
  createdAt: '',
  updatedAt: '',
});

describe('serializeItem / parseItem', () => {
  it('round-trips and tags the format version', () => {
    const data = {
      site: 'example.com',
      username: 'alice',
      password: 'p@ss "quoted"',
      notes: 'line1\nline2',
    };
    const json = serializeItem(data);
    expect(JSON.parse(json).v).toBe(1);
    expect(parseItem(json)).toEqual(data);
  });

  it('drops unexpected fields when serializing', () => {
    const json = serializeItem({ ...item('a.com'), id: 'x' } as never);
    expect(Object.keys(JSON.parse(json)).sort()).toEqual([
      'notes',
      'password',
      'site',
      'username',
      'v',
    ]);
  });

  it.each([
    ['not an object', '"str"'],
    ['wrong version', JSON.stringify({ v: 2, site: '', username: '', password: '', notes: '' })],
    ['missing field', JSON.stringify({ v: 1, site: '', username: '', password: '' })],
    ['non-string field', JSON.stringify({ v: 1, site: 1, username: '', password: '', notes: '' })],
  ])('rejects %s', (_, json) => {
    expect(() => parseItem(json)).toThrow();
  });
});

describe('filterItems', () => {
  const items = [
    item('GitHub', 'octocat', 'work account', 'secret-github'),
    item('bank.example.com', 'alice'),
    item('Email', 'alice@example.com', 'personal'),
  ];

  it('sorts by site when there is no query', () => {
    expect(filterItems(items, '  ').map((i) => i.site)).toEqual([
      'bank.example.com',
      'Email',
      'GitHub',
    ]);
  });

  it('matches site, username and notes case-insensitively', () => {
    expect(filterItems(items, 'github').map((i) => i.site)).toEqual(['GitHub']);
    expect(filterItems(items, 'ALICE').map((i) => i.site)).toEqual(['bank.example.com', 'Email']);
    expect(filterItems(items, 'personal').map((i) => i.site)).toEqual(['Email']);
  });

  it('never matches against passwords', () => {
    expect(filterItems(items, 'secret-github')).toEqual([]);
  });
});

describe('encrypted items are bound to their id and revision', () => {
  const DATA = { site: 'bank.example.com', username: 'alice', password: 'pw-1', notes: '' };
  const OTHER = { site: 'github.com', username: 'octocat', password: 'pw-2', notes: '' };
  const response = (payload: Awaited<ReturnType<typeof encryptNewItem>>): ItemResponse => ({
    ...payload,
    created_at: '',
    updated_at: '',
  });

  it('decrypts at the id and revision it was saved as', async () => {
    const key = await generateVaultKey();
    const saved = response(await encryptNewItem(DATA, key));
    expect(saved.revision).toBe(1);
    const next = response(await encryptNextRevision(saved, { ...DATA, password: 'pw-3' }, key));
    expect(next).toMatchObject({ id: saved.id, revision: 2 });
    const { items, failedIds } = await decryptVaultItems([saved, next], key);
    expect(failedIds).toEqual([]);
    expect(items.map((i) => i.password)).toEqual(['pw-1', 'pw-3']);
  });

  it('rejects contents swapped between two items', async () => {
    const key = await generateVaultKey();
    const a = response(await encryptNewItem(DATA, key));
    const b = response(await encryptNewItem(OTHER, key));
    const swapped = [
      { ...a, encrypted_data: b.encrypted_data, nonce: b.nonce },
      { ...b, encrypted_data: a.encrypted_data, nonce: a.nonce },
    ];
    expect((await decryptVaultItems(swapped, key)).failedIds).toEqual([a.id, b.id]);
  });

  it('rejects an old ciphertext relabelled as the current revision', async () => {
    const key = await generateVaultKey();
    const v1 = response(await encryptNewItem(DATA, key));
    const relabelled = { ...v1, revision: 2 };
    expect((await decryptVaultItems([relabelled], key)).failedIds).toEqual([v1.id]);
  });

  it('flags an item served at an older revision than this browser has seen', async () => {
    const key = await generateVaultKey();
    const ledger = createRevisionLedger('alice@example.com');
    const v1 = response(await encryptNewItem(DATA, key));
    const v2 = response(await encryptNextRevision(v1, { ...DATA, password: 'pw-new' }, key));
    expect((await decryptVaultItems([v2], key, ledger)).items).toHaveLength(1);

    // The server serves the old, genuinely-encrypted revision 1 again.
    const result = await decryptVaultItems([v1], key, ledger);
    expect(result.items).toEqual([]);
    expect(result.rolledBackIds).toEqual([v1.id]);
    expect(result.failedIds).toEqual([]);
  });

  it('opens items saved before binding existed as revision 0', async () => {
    const key = await generateVaultKey();
    await sodium.ready;
    const nonce = sodium.randombytes_buf(24);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      serializeItem(DATA),
      'password-manager:v1:item',
      null,
      nonce,
      key,
    );
    const legacy: ItemResponse = {
      id: crypto.randomUUID(),
      revision: 0,
      encrypted_data: toBase64(ciphertext),
      nonce: toBase64(nonce),
      created_at: '',
      updated_at: '',
    };
    const { items } = await decryptVaultItems([legacy], key);
    expect(items).toMatchObject([{ ...DATA, revision: 0 }]);
  });
});
