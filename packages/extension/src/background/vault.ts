import { decryptVaultKey, deriveKeys, deriveMasterKey } from '@password-manager/crypto';
import { fromBase64, toBase64 } from '../shared/base64';
import type { ItemSummary, PendingSavePrompt, PopupItem, Settings } from '../shared/messages';
import { securePageHost, siteMatchesHost } from '../shared/urls';
import { ApiError, createApi, describeLoginFailure, type Api } from './api';
import { decryptVaultItems, encryptVaultItem, type VaultItem, type VaultItemData } from './items';
import type { KeyValueStore } from './storage';

/**
 * The unlocked vault, owned by the background service worker.
 *
 * Where secrets live:
 * - The vault key and session token are held in this object's memory and
 *   mirrored to chrome.storage.session. MV3 terminates idle service workers
 *   after ~30s, so memory alone would lock the vault constantly; session
 *   storage is kept in memory by the browser (never written to disk), is
 *   cleared when the browser closes, and at its default access level
 *   (TRUSTED_CONTEXTS) cannot be read by content scripts.
 * - Decrypted items are cached in memory only, and re-fetched and decrypted
 *   after a service-worker restart.
 * - Nothing secret goes to chrome.storage.local, and web storage APIs
 *   (localStorage, IndexedDB) are not used at all.
 *
 * Locking (manual, inactivity timeout, OS screen lock, expired session, or
 * browser restart) zeroes the in-memory key and clears session storage.
 */

export class LockedError extends Error {
  constructor(message = 'Vault is locked') {
    super(message);
    this.name = 'LockedError';
  }
}

interface PersistedSession {
  email: string;
  token: string;
  vaultKey: string;
  serverUrl: string;
}

interface ActiveSession {
  email: string;
  token: string;
  vaultKey: Uint8Array;
  api: Api;
}

interface PendingSave {
  kind: 'new' | 'update';
  host: string;
  username: string;
  password: string;
  itemId: string | null;
  expiresAt: number;
}

export interface VaultDeps {
  /** chrome.storage.session in production. */
  session: KeyValueStore;
  fetch: typeof fetch;
  now: () => number;
  getSettings: () => Promise<Settings>;
}

const SESSION_KEY = 'session';
const ACTIVITY_KEY = 'lastActivity';
const pendingKey = (tabId: number) => `pending:${tabId}`;

/** How long a captured "save this password?" offer survives (e.g. across the post-login redirect). */
export const PENDING_SAVE_TTL_MS = 2 * 60_000;

const wipe = (...buffers: Uint8Array[]) => buffers.forEach((buffer) => buffer.fill(0));

export class Vault {
  private active: ActiveSession | null = null;
  private items: VaultItem[] | null = null;

  constructor(private readonly deps: VaultDeps) {}

  /** Restores the session from chrome.storage.session after a service-worker restart. */
  private async restore(): Promise<ActiveSession | null> {
    if (this.active) return this.active;
    const persisted = await this.deps.session.get<PersistedSession>(SESSION_KEY);
    if (!persisted) return null;
    this.active = {
      email: persisted.email,
      token: persisted.token,
      vaultKey: fromBase64(persisted.vaultKey),
      api: createApi(persisted.serverUrl, this.deps.fetch),
    };
    return this.active;
  }

  private async requireSession(): Promise<ActiveSession> {
    const session = await this.restore();
    if (!session) throw new LockedError();
    return session;
  }

  /** Runs an API call; a 401 means the server session is gone, so lock. */
  private async call<T>(fn: (session: ActiveSession) => Promise<T>): Promise<T> {
    const session = await this.requireSession();
    try {
      return await fn(session);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        await this.lock();
        throw new LockedError('Session expired — unlock again');
      }
      throw error;
    }
  }

  async isUnlocked(): Promise<boolean> {
    return (await this.restore()) !== null;
  }

  async email(): Promise<string | null> {
    return (await this.restore())?.email ?? null;
  }

  /** Same flow as the web vault: derive keys locally, prove the authHash, unwrap the vault key. */
  async unlock(emailInput: string, password: string): Promise<void> {
    const email = emailInput.trim().toLowerCase();
    if (!email || !password) throw new Error('Email and master password are required');
    const { serverUrl } = await this.deps.getSettings();
    const api = createApi(serverUrl, this.deps.fetch);

    const { kdf_salt, kdf_params } = await api.prelogin(email);
    // Rejects params below the crypto package's floor (KDF downgrade by a malicious server).
    const masterKey = await deriveMasterKey(password, fromBase64(kdf_salt), kdf_params);
    const { stretchedMasterKey, authHash } = await deriveKeys(masterKey);
    try {
      let token: string;
      try {
        ({ token } = await api.login(email, toBase64(authHash)));
      } catch (error) {
        if (error instanceof ApiError && (error.status === 401 || error.status === 429)) {
          throw new Error(describeLoginFailure(error), { cause: error });
        }
        throw error;
      }
      const wrapped = await api.getVaultKey(token);
      const vaultKey = await decryptVaultKey(
        fromBase64(wrapped.encrypted_vault_key),
        fromBase64(wrapped.vault_key_nonce),
        stretchedMasterKey,
      );

      await this.lock();
      this.active = { email, token, vaultKey, api };
      await this.deps.session.set(SESSION_KEY, {
        email,
        token,
        vaultKey: toBase64(vaultKey),
        serverUrl,
      } satisfies PersistedSession);
      await this.touch();
    } finally {
      wipe(masterKey, stretchedMasterKey, authHash);
    }
  }

  async lock(): Promise<void> {
    if (this.active) wipe(this.active.vaultKey);
    this.active = null;
    this.items = null;
    await this.deps.session.clear();
  }

  /** Records user activity with the extension, resetting the inactivity timer. */
  async touch(): Promise<void> {
    if (await this.isUnlocked()) await this.deps.session.set(ACTIVITY_KEY, this.deps.now());
  }

  /** Locks if the inactivity timeout has passed. Returns true if it locked. */
  async enforceAutoLock(): Promise<boolean> {
    if (!(await this.isUnlocked())) return false;
    const lastActivity = (await this.deps.session.get<number>(ACTIVITY_KEY)) ?? 0;
    const { autoLockMinutes } = await this.deps.getSettings();
    if (this.deps.now() - lastActivity < autoLockMinutes * 60_000) return false;
    await this.lock();
    return true;
  }

  private async getItems(): Promise<VaultItem[]> {
    if (this.items) return this.items;
    const session = await this.requireSession();
    const { items } = await this.call((s) => s.api.listItems(s.token));
    const decrypted = await decryptVaultItems(items, session.vaultKey);
    this.items = decrypted.items;
    return this.items;
  }

  async listForPopup(): Promise<PopupItem[]> {
    const items = await this.getItems();
    return items
      .map(({ id, site, username, password, notes }) => ({ id, site, username, password, notes }))
      .sort((a, b) => a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }));
  }

  /** Usernames of items matching a page — never passwords. Empty for insecure or non-web URLs. */
  async matchesForUrl(pageUrl: string): Promise<ItemSummary[]> {
    const host = securePageHost(pageUrl);
    if (!host) return [];
    const items = await this.getItems();
    return items
      .filter((item) => siteMatchesHost(item.site, host))
      .map(({ id, site, username }) => ({ id, site, username }));
  }

  /** Releases one credential, only if the item matches the (browser-reported) page URL. */
  async credentialFor(
    itemId: string,
    pageUrl: string,
  ): Promise<{ username: string; password: string; host: string }> {
    const host = securePageHost(pageUrl);
    if (!host) throw new Error('Autofill is only available on https pages');
    const item = (await this.getItems()).find((candidate) => candidate.id === itemId);
    if (!item || !siteMatchesHost(item.site, host))
      throw new Error('No matching login for this site');
    return { username: item.username, password: item.password, host };
  }

  /**
   * Records a submitted credential as a pending "save?" offer for the tab, if
   * it isn't already saved. Ignored while locked or on insecure pages.
   */
  async captureCredential(
    tabId: number,
    pageUrl: string,
    username: string,
    password: string,
  ): Promise<void> {
    const host = securePageHost(pageUrl);
    if (!host || !password || !(await this.isUnlocked())) return;
    const existing = (await this.getItems()).find(
      (item) => siteMatchesHost(item.site, host) && item.username === username,
    );
    if (existing?.password === password) {
      await this.deps.session.remove(pendingKey(tabId));
      return;
    }
    await this.deps.session.set(pendingKey(tabId), {
      kind: existing ? 'update' : 'new',
      host,
      username,
      password,
      itemId: existing?.id ?? null,
      expiresAt: this.deps.now() + PENDING_SAVE_TTL_MS,
    } satisfies PendingSave);
  }

  private async getPending(tabId: number): Promise<PendingSave | null> {
    const pending = await this.deps.session.get<PendingSave>(pendingKey(tabId));
    if (!pending) return null;
    if (pending.expiresAt <= this.deps.now()) {
      await this.deps.session.remove(pendingKey(tabId));
      return null;
    }
    return pending;
  }

  /** What the content script needs to render the prompt — never the password. */
  async pendingSavePrompt(tabId: number): Promise<PendingSavePrompt | null> {
    if (!(await this.isUnlocked())) return null;
    const pending = await this.getPending(tabId);
    return pending && { kind: pending.kind, host: pending.host, username: pending.username };
  }

  /** Saves (encrypt-then-send, like the web vault) or discards the tab's pending credential. */
  async resolvePendingSave(tabId: number, save: boolean): Promise<void> {
    const pending = await this.getPending(tabId);
    await this.deps.session.remove(pendingKey(tabId));
    if (!pending || !save) return;

    const items = await this.getItems();
    const existing = pending.itemId ? items.find((item) => item.id === pending.itemId) : undefined;
    if (existing) {
      await this.saveItem({ ...existing, password: pending.password }, existing.id);
    } else {
      await this.saveItem({
        site: pending.host,
        username: pending.username,
        password: pending.password,
        notes: '',
      });
    }
  }

  private async saveItem(data: VaultItemData, id?: string): Promise<void> {
    const session = await this.requireSession();
    const payload = await encryptVaultItem(data, session.vaultKey);
    const response = await this.call((s) =>
      id ? s.api.updateItem(s.token, id, payload) : s.api.createItem(s.token, payload),
    );
    const { site, username, password, notes } = data;
    const saved: VaultItem = { id: response.id, site, username, password, notes };
    const items = await this.getItems();
    this.items = id ? items.map((item) => (item.id === id ? saved : item)) : [...items, saved];
  }

  async forgetTab(tabId: number): Promise<void> {
    await this.deps.session.remove(pendingKey(tabId));
  }
}
