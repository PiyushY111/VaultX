import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { installFakeServer, type FakeServer } from '../../test/fakeServer';
import { createRevisionLedger } from './revisionLedger';
import { signUp, type VaultSession } from './session';
import { compareCheckpoints, vaultCheckpoint } from '@password-manager/crypto';
import { BaselineRequiredError, VaultChangedError, VaultSync } from './sync';

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
  it('is written at signup, then moves on with every write', async () => {
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

describe('first-manifest baseline (trust on first use)', () => {
  /** A vault from before manifests: items, no manifest. */
  async function legacyVault() {
    const sync = thisDevice();
    await sync.load();
    await sync.create(item('a.example.com'));
    user().manifest = null;
    localStorage.clear();
  }

  it('loads a legacy vault read-only, writing nothing, until the baseline is accepted', async () => {
    await legacyVault();
    const sync = freshDevice();
    const writes = () => server.requests.filter((r) => r.method !== 'GET').length;
    const before = writes();
    const loaded = await sync.load();
    expect(loaded.items).toHaveLength(1);
    expect(loaded.baseline).toMatchObject({
      reason: 'none',
      itemCount: 1,
      previouslySeenVersion: 0,
    });
    expect(loaded.baseline!.newestUpdate).toEqual(expect.any(String));
    expect(sync.trustedManifest()).toBeNull();
    await expect(sync.create(item('b.example.com'))).rejects.toThrow(BaselineRequiredError);
    expect(() => sync.currentManifest()).toThrow(BaselineRequiredError);
    expect(writes()).toBe(before);
    expect(user().manifest).toBeNull();

    await sync.acceptBaseline(loaded.items);
    expect(user().manifest!.version).toBe(1);
    expect(sync.baseline()).toBeNull();
    await sync.create(item('b.example.com'));
    expect(user().manifest!.version).toBe(2);
  });

  it('records the accepted baseline in the revision ledger', async () => {
    await legacyVault();
    const ledger = createRevisionLedger(EMAIL);
    const sync = new VaultSync(session, ledger);
    await sync.acceptBaseline((await sync.load()).items);
    expect(ledger.baseline()).toMatchObject({ version: 1, itemCount: 1, reason: 'none' });
    expect(ledger.manifestVersion()).toBe(1);
    // And the next load, on this device, has nothing to ask.
    expect((await thisDevice().load()).baseline).toBeNull();
  });

  it('a declined baseline stays pending, and nothing is written, load after load', async () => {
    await legacyVault();
    for (let i = 0; i < 2; i++) {
      const loaded = await thisDevice().load();
      expect(loaded.baseline?.reason).toBe('none');
    }
    expect(user().manifest).toBeNull();
  });

  it('asks too when a manifest this browser saw has gone missing, and says so', async () => {
    const sync = thisDevice();
    await sync.load();
    await sync.create(item('a.example.com'));
    await sync.create(item('b.example.com'));
    user().manifest = null;
    const ledger = createRevisionLedger(EMAIL);
    const again = new VaultSync(session, ledger);
    const loaded = await again.load();
    expect(loaded.warnings.manifest).toBe('missing');
    expect(loaded.baseline).toMatchObject({ reason: 'missing', previouslySeenVersion: 3 });
    await again.acceptBaseline(loaded.items);
    // Accepting starts over from the new baseline, so it isn't reported as stale later.
    expect(ledger.manifestVersion()).toBe(1);
    expect((await thisDevice().load()).warnings.manifest).toBeNull();
  });

  it('asks when the manifest fails its integrity check, and writes the next version', async () => {
    const sync = thisDevice();
    await sync.load();
    await sync.create(item('a.example.com'));
    user().manifest = { ...user().manifest!, version: 7 };
    const fresh = freshDevice();
    const loaded = await fresh.load();
    expect(loaded.baseline?.reason).toBe('tampered');
    await fresh.acceptBaseline(loaded.items);
    expect(user().manifest!.version).toBe(8);
  });
});

describe('vault checkpoint across devices', () => {
  const checkpointOf = async (sync: VaultSync) =>
    vaultCheckpoint(sync.trustedManifest()!, session.vaultKey);

  it('matches on two devices that see the same vault', async () => {
    const here = thisDevice();
    await here.load();
    await here.create(item('a.example.com'));
    const there = freshDevice();
    await there.load();
    expect(await compareCheckpoints(await checkpointOf(there), await checkpointOf(here))).toBe(
      'match',
    );
  });

  it('shows a rollback when a new device is served a consistent older copy', async () => {
    const here = thisDevice();
    await here.load();
    await here.create(item('a.example.com'));
    const oldManifest = { ...user().manifest! };
    const oldItems = new Map([...server.items].map(([id, value]) => [id, { ...value }]));
    await here.create(item('b.example.com'));
    const trusted = await checkpointOf(here);

    // The server rewinds everything to before b. A new device sees nothing wrong...
    user().manifest = oldManifest;
    server.items.clear();
    for (const [id, value] of oldItems) server.items.set(id, value);
    const newDevice = freshDevice();
    const loaded = await newDevice.load();
    expect(loaded.warnings.manifest).toBeNull();
    // ...until it's given the checkpoint from the device that saw the newer vault.
    expect(await compareCheckpoints(await checkpointOf(newDevice), trusted)).toBe('rollback');
  });

  it('shows a mismatch for a different vault at the same version', async () => {
    const here = thisDevice();
    await here.load();
    const start = { ...user().manifest! };
    await here.create(item('a.example.com'));
    const mine = await checkpointOf(here);

    // The server rewinds and lets another change take the same version number.
    user().manifest = start;
    server.items.clear();
    const other = freshDevice();
    await other.load();
    await other.create(item('different.example.com'));
    const theirs = await checkpointOf(other);
    expect(theirs.version).toBe(mine.version);
    expect(await compareCheckpoints(theirs, mine)).toBe('mismatch');
  });
});
