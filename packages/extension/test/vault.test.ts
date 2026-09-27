import { beforeEach, describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS } from '../src/background/settings';
import { LockedError, PENDING_SAVE_TTL_MS, Vault } from '../src/background/vault';
import { MemoryStore, SERVER, createFakeServer } from './helpers';

const EMAIL = 'alice@example.com';
const PASSWORD = 'MASTER-correct-horse-battery-staple';
const GITHUB = {
  site: 'github.com',
  username: 'octocat',
  password: 'gh-ITEM-PASSWORD',
  notes: 'work',
};
const BANK = {
  site: 'https://bank.example.com/login',
  username: 'alice',
  password: 'bank-ITEM-PASSWORD',
  notes: '',
};

let server: ReturnType<typeof createFakeServer>;
let session: MemoryStore;
let clock: number;
let vaultKey: Uint8Array;
let githubId: string;

function makeVault(autoLockMinutes = 15) {
  return new Vault({
    session,
    fetch: server.fetch,
    now: () => clock,
    getSettings: async () => ({ ...DEFAULT_SETTINGS, serverUrl: SERVER, autoLockMinutes }),
  });
}

beforeEach(async () => {
  server = createFakeServer();
  session = new MemoryStore();
  clock = 1_000_000;
  vaultKey = await server.register(EMAIL, PASSWORD);
  githubId = await server.seedItem(vaultKey, GITHUB);
  await server.seedItem(vaultKey, BANK);
});

describe('unlock', () => {
  it('derives keys locally and decrypts items without sending the password or keys', async () => {
    const vault = makeVault();
    await vault.unlock(' Alice@Example.com ', PASSWORD);
    expect(await vault.isUnlocked()).toBe(true);
    expect((await vault.listForPopup()).map((i) => i.site)).toEqual([
      'github.com',
      'https://bank.example.com/login',
    ]);

    const traffic = server.requests.map((r) => `${r.url} ${r.body}`).join('\n');
    expect(traffic).not.toContain(PASSWORD);
    expect(traffic).not.toContain(GITHUB.password);
    expect(traffic).not.toContain(Buffer.from(vaultKey).toString('base64'));
  });

  it('rejects a wrong password and stays locked', async () => {
    const vault = makeVault();
    await expect(vault.unlock(EMAIL, 'wrong-password')).rejects.toThrow(
      'Incorrect email or master password',
    );
    expect(await vault.isUnlocked()).toBe(false);
    expect(session.data.size).toBe(0);
  });

  it('keeps the vault key only in session storage (memory-only in Chrome), never in item form', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    expect([...session.data.keys()].sort()).toEqual(['lastActivity', 'session']);
    const stored = JSON.stringify([...session.data.values()]);
    expect(stored).not.toContain(PASSWORD);
    expect(stored).not.toContain(GITHUB.password);
  });
});

describe('service worker restart', () => {
  it('restores the unlocked session from session storage without the password', async () => {
    await makeVault().unlock(EMAIL, PASSWORD);
    const restarted = makeVault(); // Fresh instance, same chrome.storage.session.
    expect(await restarted.isUnlocked()).toBe(true);
    expect(
      (await restarted.matchesForUrl('https://github.com/login')).map((m) => m.username),
    ).toEqual(['octocat']);
  });

  it('is locked after a browser restart (session storage is empty)', async () => {
    await makeVault().unlock(EMAIL, PASSWORD);
    session = new MemoryStore();
    expect(await makeVault().isUnlocked()).toBe(false);
  });
});

describe('lock and auto-lock', () => {
  it('lock wipes the in-memory key and clears session storage', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    const persisted = session.data.get('session') as { vaultKey: string };
    expect(persisted.vaultKey).toBeTruthy();
    const keyRef = (vault as unknown as { active: { vaultKey: Uint8Array } }).active.vaultKey;

    await vault.lock();
    expect(keyRef.every((byte) => byte === 0)).toBe(true);
    expect(session.data.size).toBe(0);
    await expect(vault.listForPopup()).rejects.toThrow(LockedError);
  });

  it('locks after the inactivity timeout, and activity resets the timer', async () => {
    const vault = makeVault(5);
    await vault.unlock(EMAIL, PASSWORD);

    clock += 4 * 60_000;
    expect(await vault.enforceAutoLock()).toBe(false);
    await vault.touch();
    clock += 4 * 60_000;
    expect(await vault.enforceAutoLock()).toBe(false);

    clock += 60_000;
    expect(await vault.enforceAutoLock()).toBe(true);
    expect(await vault.isUnlocked()).toBe(false);
    expect(session.data.size).toBe(0);
  });

  it('locks when the server rejects the session', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    server.expireSessions();
    const fresh = makeVault(); // No cached items, so it must hit the server.
    await expect(fresh.listForPopup()).rejects.toThrow('Session expired');
    expect(await fresh.isUnlocked()).toBe(false);
  });
});

describe('autofill matching', () => {
  it('returns usernames (not passwords) of items matching the page host', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    const matches = await vault.matchesForUrl('https://github.com/login');
    expect(matches).toEqual([{ id: githubId, site: 'github.com', username: 'octocat' }]);
    expect(JSON.stringify(matches)).not.toContain(GITHUB.password);
    expect(await vault.matchesForUrl('https://bank.example.com/')).toHaveLength(1);
  });

  it('offers nothing on other, lookalike or insecure sites', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    for (const url of [
      'https://evil.com',
      'https://github.com.evil.com',
      'http://github.com/login',
      'file:///x',
    ]) {
      expect(await vault.matchesForUrl(url)).toEqual([]);
    }
  });

  it('releases a credential only for the matching site', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    await expect(vault.credentialFor(githubId, 'https://github.com/login')).resolves.toMatchObject({
      username: 'octocat',
      password: GITHUB.password,
    });
    await expect(vault.credentialFor(githubId, 'https://evil.com/login')).rejects.toThrow(
      'No matching login',
    );
    await expect(vault.credentialFor(githubId, 'http://github.com/login')).rejects.toThrow('https');
  });
});

describe('save prompt', () => {
  const TAB = 7;

  it('offers to save a new credential and saves it encrypted', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    await vault.captureCredential(
      TAB,
      'https://news.example.org/login',
      'reader',
      'NEW-SITE-PASSWORD',
    );

    expect(await vault.pendingSavePrompt(TAB)).toEqual({
      kind: 'new',
      host: 'news.example.org',
      username: 'reader',
    });
    expect(JSON.stringify(await vault.pendingSavePrompt(TAB))).not.toContain('NEW-SITE-PASSWORD');

    await vault.resolvePendingSave(TAB, true);
    expect(await vault.pendingSavePrompt(TAB)).toBeNull();
    const post = server.requests.at(-1)!;
    expect(post.method).toBe('POST');
    expect(post.body).not.toContain('NEW-SITE-PASSWORD');
    expect(post.body).not.toContain('reader');

    // A fresh instance decrypts it from the server.
    const again = makeVault();
    expect(await again.matchesForUrl('https://news.example.org/')).toMatchObject([
      { username: 'reader' },
    ]);
  });

  it('offers an update when the password changed, and PUTs it', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    await vault.captureCredential(TAB, 'https://github.com/session', 'octocat', 'ROTATED');
    expect(await vault.pendingSavePrompt(TAB)).toMatchObject({
      kind: 'update',
      username: 'octocat',
    });
    await vault.resolvePendingSave(TAB, true);
    expect(server.requests.at(-1)!.method).toBe('PUT');
    expect((await vault.credentialFor(githubId, 'https://github.com')).password).toBe('ROTATED');
  });

  it('does not offer to save a credential that is already saved', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    await vault.captureCredential(TAB, 'https://github.com/session', 'octocat', GITHUB.password);
    expect(await vault.pendingSavePrompt(TAB)).toBeNull();
  });

  it('ignores submissions while locked or on insecure pages', async () => {
    const vault = makeVault();
    await vault.captureCredential(TAB, 'https://news.example.org/login', 'reader', 'pw');
    expect(session.data.size).toBe(0);
    await vault.unlock(EMAIL, PASSWORD);
    await vault.captureCredential(TAB, 'http://news.example.org/login', 'reader', 'pw');
    expect(await vault.pendingSavePrompt(TAB)).toBeNull();
  });

  it('discards on "Not now", expires, and is cleared by locking', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    const requestsBefore = server.requests.length;
    await vault.captureCredential(TAB, 'https://a.example.org', 'u', 'p1');
    await vault.resolvePendingSave(TAB, false);
    expect(await vault.pendingSavePrompt(TAB)).toBeNull();
    expect(server.requests.slice(requestsBefore).some((r) => r.method === 'POST')).toBe(false);

    await vault.captureCredential(TAB, 'https://a.example.org', 'u', 'p2');
    clock += PENDING_SAVE_TTL_MS + 1;
    expect(await vault.pendingSavePrompt(TAB)).toBeNull();

    await vault.captureCredential(TAB, 'https://a.example.org', 'u', 'p3');
    await vault.lock();
    await vault.unlock(EMAIL, PASSWORD);
    expect(await vault.pendingSavePrompt(TAB)).toBeNull();
  });

  it('keeps pending saves per tab', async () => {
    const vault = makeVault();
    await vault.unlock(EMAIL, PASSWORD);
    await vault.captureCredential(1, 'https://a.example.org', 'u', 'p');
    expect(await vault.pendingSavePrompt(2)).toBeNull();
    expect(await vault.pendingSavePrompt(1)).not.toBeNull();
  });
});
