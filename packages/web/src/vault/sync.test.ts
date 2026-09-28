import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { installFakeServer, type FakeServer } from '../../test/fakeServer';
import { createRevisionLedger } from './revisionLedger';
import { signUp, type VaultSession } from './session';
import { VaultChangedError, VaultSync } from './sync';

const EMAIL = 'alice@example.com';
const PASSWORD = 'MASTER-correct-horse-battery-staple-41';
const item = (site: string) => ({ site, username: 'u', password: `pw-${site}`, notes: '' });

let server: FakeServer;
let session: VaultSession;

beforeEach(async () => {
  localStorage.clear();
  server = installFakeServer();
  session = await signUp(EMAIL, PASSWORD);
});

afterEach(() => server.restore());

/** A browser that has never seen this vault: no ledger. */
const freshDevice = () => new VaultSync(session, createRevisionLedger(EMAIL, null));
const thisDevice = () => new VaultSync(session, createRevisionLedger(EMAIL));
const user = () => server.users.get(EMAIL)!;

describe('vault manifest', () => {
  it('is written on first load, then moves on with every write', async () => {
    const sync = thisDevice();
    const empty = await sync.load();
    expect(empty.items).toEqual([]);
    expect(user().manifest!.version).toBe(1);

    const a = await sync.create(item('a.example.com'));
    const b = await sync.create(item('b.example.com'));
    await sync.update(a, { ...item('a.example.com'), password: 'new' });
    await sync.remove(b.id);
    expect(user().manifest!.version).toBe(5);
    expect(sync.currentManifest().items).toEqual({ [a.id]: 2 });

    const loaded = await freshDevice().load();
    expect(loaded.items.map((i) => i.site)).toEqual(['a.example.com']);
    expect(loaded.lastChanged).toMatchObject({ by: 'web' });
  });

  it('catches an old revision even on a device that has never seen the vault', async () => {
    const sync = thisDevice();
    await sync.load();
    const a = await sync.create(item('a.example.com'));
    const v1 = { ...server.items.get(a.id)! };
    await sync.update(a, { ...item('a.example.com'), password: 'rotated' });

    server.items.set(a.id, v1); // genuine, older ciphertext
    const loaded = await freshDevice().load();
    expect(loaded.items).toEqual([]);
    expect(loaded.warnings.rolledBackIds).toEqual([a.id]);
  });

  it('reports items the server hides', async () => {
    const sync = thisDevice();
    await sync.load();
    const a = await sync.create(item('a.example.com'));
    server.items.delete(a.id);
    const loaded = await freshDevice().load();
    expect(loaded.warnings.missingIds).toEqual([a.id]);
  });

  it('hides a deleted item the server brings back', async () => {
    const sync = thisDevice();
    await sync.load();
    const a = await sync.create(item('a.example.com'));
    const copy = { ...server.items.get(a.id)! };
    await sync.remove(a.id);
    server.items.set(a.id, copy);
    const loaded = await freshDevice().load();
    expect(loaded.items).toEqual([]);
    expect(loaded.warnings.unexpectedIds).toEqual([a.id]);
  });

  it('notices a whole older copy of the vault on a device that saw a newer one', async () => {
    const sync = thisDevice();
    await sync.load();
    await sync.create(item('a.example.com'));
    const oldManifest = { ...user().manifest! };
    const oldItems = new Map([...server.items].map(([id, value]) => [id, { ...value }]));
    await sync.create(item('b.example.com'));

    // Consistent snapshot from before b: fine to a fresh device, stale to this one.
    user().manifest = oldManifest;
    server.items.clear();
    for (const [id, value] of oldItems) server.items.set(id, value);
    expect((await freshDevice().load()).warnings.manifest).toBeNull();
    expect((await thisDevice().load()).warnings.manifest).toBe('stale');
  });

  it('flags a manifest that fails its integrity check, or goes missing', async () => {
    const sync = thisDevice();
    await sync.load();
    await sync.create(item('a.example.com'));
    const good = { ...user().manifest! };

    user().manifest = { ...good, version: good.version + 1 };
    expect((await freshDevice().load()).warnings.manifest).toBe('tampered');

    user().manifest = null;
    expect((await thisDevice().load()).warnings.manifest).toBe('missing');
  });

  it('refuses to write over a change made elsewhere', async () => {
    const here = thisDevice();
    const elsewhere = freshDevice();
    await here.load();
    await elsewhere.load();
    await elsewhere.create(item('b.example.com'));
    await expect(here.create(item('a.example.com'))).rejects.toThrow(VaultChangedError);
    // After reloading it works, and nothing was lost.
    await here.load();
    await here.create(item('a.example.com'));
    expect(Object.keys(here.currentManifest().items)).toHaveLength(2);
  });
});

describe('createMany (import)', () => {
  it('saves in batches, each with its manifest change', async () => {
    const sync = thisDevice();
    await sync.load();
    const data = Array.from({ length: VaultSync.BATCH_SIZE + 3 }, (_, i) =>
      item(`site-${i}.example.com`),
    );
    const progress: number[] = [];
    const saved = await sync.createMany(data, (count) => progress.push(count));
    expect(saved).toHaveLength(data.length);
    expect(progress).toEqual([VaultSync.BATCH_SIZE, data.length]);
    expect(user().manifest!.version).toBe(3); // first manifest + two batches
    const loaded = await freshDevice().load();
    expect(loaded.items).toHaveLength(data.length);
    expect(loaded.warnings.missingIds).toEqual([]);
  });
});
