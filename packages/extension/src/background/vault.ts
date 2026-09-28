import {
  DecryptionError,
  checkAgainstManifest,
  parseTotp,
  totpCode,
  decryptManifest,
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
  encryptManifest,
  nextManifest,
  type VaultManifest,
} from '@password-manager/crypto';
import { fromBase64, toBase64 } from '../shared/base64';
import type {
  ItemSummary,
  PendingSavePrompt,
  PopupItem,
  Settings,
  TotpCodeResponse,
  VaultWarnings,
} from '../shared/messages';
import { securePageHost, siteMatchesHost } from '../shared/urls';
import {
  ApiError,
  createApi,
  describeLoginFailure,
  needsSecondFactor,
  passkeyOnly,
  type Api,
  type ManifestPayload,
  type SecondFactor,
} from './api';
import {
  decryptVaultItems,
  encryptVaultItem,
  isLogin,
  withPasswordHistory,
  type VaultItem,
  type VaultItemData,
} from './items';
import { createRevisionLedger } from './revisions';
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
 * browser restart) zeroes the in-memory key, clears session storage, and
 * ends the server session.
 */

/** The password was right; the account needs a two-factor code ({@link Vault.unlockSecondFactor}). */
export class SecondFactorRequiredError extends Error {
  override name = 'SecondFactorRequiredError';

  constructor(
    message: string,
    /** Only a passkey or a recovery code will do; the extension can offer only the latter. */
    readonly passkeyOnly = false,
  ) {
    super(message);
  }
}

const NO_WARNINGS: VaultWarnings = {
  failed: 0,
  rolledBack: 0,
  missing: 0,
  unexpected: 0,
  manifest: null,
};

const CLIENT_NAME = 'extension';
/** How long a sign-in waits for its two-factor code. */
const SECOND_FACTOR_TTL_MS = 5 * 60_000;

/** A sign-in waiting for its two-factor code. Memory only: a worker restart means starting over. */
interface PendingLogin {
  email: string;
  serverUrl: string;
  api: Api;
  stretchedMasterKey: Uint8Array;
  authHash: Uint8Array;
  expiresAt: number;
}

const isManifestConflict = (error: unknown) =>
  error instanceof ApiError && error.status === 409 && 'manifest_version' in error.details;

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
  /** chrome.storage.local in production. Holds only non-secret data (the revision ledger). */
  local: KeyValueStore;
  fetch: typeof fetch;
  now: () => number;
  getSettings: () => Promise<Settings>;
  /** Called after every lock (e.g. to clear a copied password). */
  onLock?: () => Promise<void>;
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
  /** The manifest the next write builds on; loaded with the items. */
  private manifest: VaultManifest | null = null;
  private warnings: VaultWarnings = NO_WARNINGS;
  private pendingLogin: PendingLogin | null = null;

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

  /**
   * Same flow as the web vault: derive keys locally, prove the authHash,
   * unwrap the vault key. Throws {@link SecondFactorRequiredError} if the
   * account has two-factor on; the derived keys then wait in memory for
   * {@link unlockSecondFactor}, so Argon2id doesn't run twice.
   */
  async unlock(emailInput: string, password: string): Promise<void> {
    const email = emailInput.trim().toLowerCase();
    if (!email || !password) throw new Error('Email and master password are required');
    const { serverUrl } = await this.deps.getSettings();
    const api = createApi(serverUrl, this.deps.fetch);

    const { kdf_salt, kdf_params } = await api.prelogin(email);
    // Rejects params below the crypto package's floor (KDF downgrade by a malicious server).
    const masterKey = await deriveMasterKey(password, fromBase64(kdf_salt), kdf_params);
    const keys = await deriveKeys(masterKey);
    wipe(masterKey);
    this.clearPendingLogin();
    let handedOff = false;
    try {
      await this.finishUnlock(email, serverUrl, api, keys);
    } catch (error) {
      if (needsSecondFactor(error instanceof Error ? (error.cause ?? error) : error)) {
        handedOff = true;
        this.pendingLogin = {
          email,
          serverUrl,
          api,
          ...keys,
          expiresAt: this.deps.now() + SECOND_FACTOR_TTL_MS,
        };
        const cause = (error as Error).cause;
        throw new SecondFactorRequiredError(
          (error as Error).message,
          cause instanceof ApiError && passkeyOnly(cause),
        );
      }
      throw error;
    } finally {
      if (!handedOff) wipe(keys.stretchedMasterKey, keys.authHash);
    }
  }

  /** Completes a sign-in with a code from the authenticator app, or a recovery code. */
  async unlockSecondFactor(code: string, recovery: boolean): Promise<void> {
    const pending = this.pendingLogin;
    if (!pending || pending.expiresAt <= this.deps.now()) {
      this.clearPendingLogin();
      throw new Error('This sign-in expired. Enter your master password again.');
    }
    const factor: SecondFactor = recovery
      ? { recovery_code: code.trim() }
      : { totp_code: code.trim() };
    // A wrong code throws here and keeps the sign-in waiting for another try.
    await this.finishUnlock(pending.email, pending.serverUrl, pending.api, pending, factor);
  }

  private clearPendingLogin(): void {
    if (this.pendingLogin) wipe(this.pendingLogin.stretchedMasterKey, this.pendingLogin.authHash);
    this.pendingLogin = null;
  }

  private async finishUnlock(
    email: string,
    serverUrl: string,
    api: Api,
    { stretchedMasterKey, authHash }: { stretchedMasterKey: Uint8Array; authHash: Uint8Array },
    factor?: SecondFactor,
  ): Promise<void> {
    let token: string;
    try {
      ({ token } = await api.login(email, toBase64(authHash), factor));
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

    await this.lock(); // Also wipes a pending two-factor sign-in, which is done now.
    this.active = { email, token, vaultKey, api };
    await this.deps.session.set(SESSION_KEY, {
      email,
      token,
      vaultKey: toBase64(vaultKey),
      serverUrl,
    } satisfies PersistedSession);
    await this.touch();
  }

  async lock(): Promise<void> {
    const session = await this.restore();
    if (session) wipe(session.vaultKey);
    this.active = null;
    this.items = null;
    this.manifest = null;
    this.warnings = NO_WARNINGS;
    this.clearPendingLogin();
    await this.deps.session.clear();
    // Unlocking logs in afresh, so the old server session would only linger.
    // Best effort, and not awaited: the vault is already locked.
    session?.api.logout(session.token).catch(() => {});
    await this.deps.onLock?.().catch(() => {});
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

  private ledger(session: ActiveSession) {
    return createRevisionLedger(this.deps.local, session.email);
  }

  private async encryptManifestPayload(
    manifest: VaultManifest,
    vaultKey: Uint8Array,
  ): Promise<ManifestPayload> {
    const { ciphertext, nonce } = await encryptManifest(manifest, vaultKey);
    return {
      version: manifest.version,
      encrypted_data: toBase64(ciphertext),
      nonce: toBase64(nonce),
    };
  }

  /**
   * Loads and decrypts the vault, checking it against its manifest like the
   * web vault does (see packages/web/src/vault/sync.ts). Items that fail to
   * decrypt, are older than a revision already seen, or don't match the
   * manifest are left out and counted in {@link vaultWarnings}.
   */
  private async getItems(): Promise<VaultItem[]> {
    if (this.items) return this.items;
    const session = await this.requireSession();
    const ledger = this.ledger(session);
    const { items: responses, manifest: payload } = await this.call((s) =>
      s.api.listItems(s.token),
    );
    const decrypted = await decryptVaultItems(responses, session.vaultKey, ledger);
    const warnings: VaultWarnings = {
      ...NO_WARNINGS,
      failed: decrypted.failed,
      rolledBack: decrypted.rolledBack,
    };

    let manifest: VaultManifest | null = null;
    if (payload) {
      try {
        manifest = await decryptManifest(
          fromBase64(payload.encrypted_data),
          fromBase64(payload.nonce),
          session.vaultKey,
          payload.version,
        );
      } catch (error) {
        if (!(error instanceof DecryptionError)) throw error;
        warnings.manifest = 'tampered';
      }
    }
    const seenVersion = await ledger.manifestVersion();
    if (manifest && manifest.version < seenVersion) warnings.manifest = 'stale';
    if (!payload && seenVersion > 0) warnings.manifest = 'missing';

    let items = decrypted.items;
    if (manifest) {
      const check = checkAgainstManifest(manifest, responses);
      const hidden = new Set([...check.unexpected, ...check.mismatched]);
      warnings.missing = check.missing.length;
      warnings.unexpected = check.unexpected.length;
      warnings.rolledBack += items.filter((item) => check.mismatched.includes(item.id)).length;
      items = items.filter((item) => !hidden.has(item.id));
      await ledger.recordManifest(manifest.version);
    } else {
      // No usable manifest: start one from what could be verified, at the
      // version after the server's, so the next write repairs it.
      manifest = {
        version: payload?.version ?? 0,
        items: Object.fromEntries(items.map((item) => [item.id, item.revision])),
        updatedAt: '',
        updatedBy: '',
      };
      if (!payload) {
        // A vault that never had one gets its first right away.
        const first = nextManifest(manifest, {}, CLIENT_NAME);
        await this.call(async (s) =>
          s.api.putManifest(s.token, await this.encryptManifestPayload(first, s.vaultKey)),
        ).catch((error: unknown) => {
          if (!isManifestConflict(error)) throw error;
        });
        manifest = first;
        await ledger.recordManifest(first.version);
      }
    }
    this.manifest = manifest;
    this.warnings = warnings;
    this.items = items;
    return items;
  }

  /** What the last load's integrity checks found, for the popup to show. */
  async vaultWarnings(): Promise<VaultWarnings> {
    await this.getItems();
    return this.warnings;
  }

  /** The vault's logins. Notes, cards and identities live in the web vault only. */
  private async getLogins(): Promise<VaultItem[]> {
    return (await this.getItems()).filter(isLogin);
  }

  async listForPopup(): Promise<PopupItem[]> {
    const items = await this.getLogins();
    return items
      .map(({ id, site, username, password, notes, totp }) => ({
        id,
        site,
        username,
        password,
        notes,
        hasTotp: Boolean(totp),
      }))
      .sort((a, b) => a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }));
  }

  private async totpCodeOf(item: VaultItem | undefined): Promise<TotpCodeResponse> {
    if (!item?.totp) throw new Error('That login has no two-factor code');
    return totpCode(parseTotp(item.totp), this.deps.now());
  }

  /** The current two-factor code of an item, for the popup (a trusted extension page). */
  async totpCodeForPopup(itemId: string): Promise<TotpCodeResponse> {
    return this.totpCodeOf((await this.getItems()).find((item) => item.id === itemId));
  }

  /** Items matching a page that have a two-factor secret: usernames only. */
  async totpMatchesForUrl(pageUrl: string): Promise<ItemSummary[]> {
    const host = securePageHost(pageUrl);
    if (!host) return [];
    return (await this.getLogins())
      .filter((item) => item.totp && siteMatchesHost(item.site, host))
      .map(({ id, site, username }) => ({ id, site, username }));
  }

  /** The current code for an item, only if it matches the (browser-reported) page URL. */
  async totpCodeForUrl(itemId: string, pageUrl: string): Promise<TotpCodeResponse> {
    const host = securePageHost(pageUrl);
    if (!host) throw new Error('Autofill is only available on https pages');
    const item = (await this.getLogins()).find((candidate) => candidate.id === itemId);
    if (!item || !siteMatchesHost(item.site, host))
      throw new Error('No matching login for this site');
    return this.totpCodeOf(item);
  }

  /** Usernames of items matching a page — never passwords. Empty for insecure or non-web URLs. */
  async matchesForUrl(pageUrl: string): Promise<ItemSummary[]> {
    const host = securePageHost(pageUrl);
    if (!host) return [];
    const items = await this.getLogins();
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
    const item = (await this.getLogins()).find((candidate) => candidate.id === itemId);
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
    const existing = (await this.getLogins()).find(
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

    if (pending.itemId) {
      const itemId = pending.itemId;
      await this.saveItem(
        (current) =>
          current &&
          withPasswordHistory(
            current,
            { ...current, password: pending.password },
            new Date(this.deps.now()),
          ),
        itemId,
      );
    } else {
      await this.saveItem(() => ({
        site: pending.host,
        username: pending.username,
        password: pending.password,
        notes: '',
      }));
    }
  }

  /** Encrypts and saves a login entered in the popup, like the web vault's "Add item". */
  async addItem(data: VaultItemData): Promise<void> {
    const site = data.site.trim();
    if (!site) throw new Error('Enter the site for this login');
    await this.saveItem(() => ({ ...data, site }));
  }

  /**
   * Saves a new item (revision 1, fresh id), or the next revision of the item
   * `existingId`. `build` makes the data from the item's current copy. The
   * write carries the vault's next manifest; if the vault changed elsewhere
   * meanwhile, it reloads and tries once more on the fresh copy.
   */
  private async saveItem(
    build: (current: VaultItem | undefined) => VaultItemData | undefined,
    existingId?: string,
  ): Promise<void> {
    for (let attempt = 0; ; attempt++) {
      const items = await this.getItems();
      const session = await this.requireSession();
      const existing = existingId ? items.find((item) => item.id === existingId) : undefined;
      if (existingId && !existing) throw new Error('That login is no longer in your vault');
      const data = build(existing);
      if (!data) return;
      const payload = existing
        ? await encryptVaultItem(data, session.vaultKey, existing.id, existing.revision + 1)
        : await encryptVaultItem(data, session.vaultKey, crypto.randomUUID(), 1);
      const manifest = nextManifest(
        this.manifest!,
        { set: [{ id: payload.id, revision: payload.revision }] },
        CLIENT_NAME,
      );
      const manifestPayload = await this.encryptManifestPayload(manifest, session.vaultKey);
      let response: Awaited<ReturnType<Api['createItem']>>;
      try {
        response = await this.call((s) =>
          existing
            ? s.api.updateItem(s.token, payload, manifestPayload)
            : s.api.createItem(s.token, payload, manifestPayload),
        );
      } catch (error) {
        if (error instanceof ApiError && error.status === 409) {
          // Changed elsewhere since we loaded it: reload, and retry once.
          this.items = null;
          if (isManifestConflict(error) && attempt === 0) continue;
        }
        throw error;
      }
      const ledger = this.ledger(session);
      await ledger.record([response]);
      await ledger.recordManifest(manifest.version);
      this.manifest = manifest;
      const saved: VaultItem = { ...data, id: response.id, revision: response.revision };
      this.items = existing
        ? items.map((item) => (item.id === existing.id ? saved : item))
        : [...items, saved];
      return;
    }
  }

  async forgetTab(tabId: number): Promise<void> {
    await this.deps.session.remove(pendingKey(tabId));
  }
}
