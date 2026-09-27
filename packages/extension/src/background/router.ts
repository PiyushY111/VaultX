import {
  CONTENT_REQUEST_TYPES,
  POPUP_REQUEST_TYPES,
  type ContentRequest,
  type FillCredentialMessage,
  type PopupRequest,
  type Response,
  type VaultState,
} from '../shared/messages';
import { loadLastEmail, loadSettings, saveLastEmail, saveSettings } from './settings';
import type { KeyValueStore } from './storage';
import { LockedError, type Vault } from './vault';

/**
 * Who sent a message, as established by the browser — not by the message.
 *
 * - popup: our own popup.html (extension origin; web pages can't forge it).
 * - content: our content script in the top frame of an http(s) tab. `url` is
 *   the browser-reported URL of that document and is what every
 *   domain check uses; the content script's claims are never trusted for it.
 *
 * Anything else (other extensions, subframes, unknown pages) is rejected.
 * The manifest also omits `externally_connectable`, so web pages can't
 * message the extension at all.
 */
export type Sender = { kind: 'popup' } | { kind: 'content'; tabId: number; url: string };

export function classifySender(
  sender: chrome.runtime.MessageSender,
  extensionId: string,
  popupUrl: string,
): Sender | null {
  if (sender.id !== extensionId) return null;
  if (
    sender.url &&
    (sender.url === popupUrl ||
      sender.url.startsWith(`${popupUrl}?`) ||
      sender.url.startsWith(`${popupUrl}#`))
  ) {
    return { kind: 'popup' };
  }
  if (
    sender.tab?.id !== undefined &&
    sender.frameId === 0 &&
    sender.url &&
    /^https?:\/\//.test(sender.url)
  ) {
    return { kind: 'content', tabId: sender.tab.id, url: sender.url };
  }
  return null;
}

export interface RouterDeps {
  vault: Vault;
  settingsStore: KeyValueStore;
  clipboard: { scheduleClear(): Promise<void> };
  tabs: {
    getUrl(tabId: number): Promise<string | undefined>;
    sendFill(tabId: number, message: FillCredentialMessage & { host: string }): Promise<void>;
    /** Lets open tabs that showed "locked" re-offer autofill. */
    notifyUnlocked(): Promise<void>;
  };
}

const ok = <T>(data: T): Response<T> => ({ ok: true, data });

function isRequest(message: unknown): message is { type: string } {
  return (
    typeof message === 'object' &&
    message !== null &&
    typeof (message as { type?: unknown }).type === 'string'
  );
}

export async function handleMessage(
  message: unknown,
  sender: Sender | null,
  deps: RouterDeps,
): Promise<Response<unknown>> {
  if (!sender || !isRequest(message)) return { ok: false, error: 'Not allowed' };
  try {
    // Check the inactivity timeout on every request, not just on the alarm,
    // since alarms can fire late.
    await deps.vault.enforceAutoLock();

    if (sender.kind === 'popup' && POPUP_REQUEST_TYPES.has(message.type as PopupRequest['type'])) {
      return await handlePopup(message as PopupRequest, deps);
    }
    if (
      sender.kind === 'content' &&
      CONTENT_REQUEST_TYPES.has(message.type as ContentRequest['type'])
    ) {
      return await handleContent(message as ContentRequest, sender, deps);
    }
    return { ok: false, error: 'Not allowed' };
  } catch (error) {
    if (error instanceof LockedError) return { ok: false, error: error.message, locked: true };
    return { ok: false, error: error instanceof Error ? error.message : 'Unexpected error' };
  }
}

async function handlePopup(request: PopupRequest, deps: RouterDeps): Promise<Response<unknown>> {
  const { vault, settingsStore, tabs } = deps;
  // Any popup interaction counts as activity.
  if (request.type !== 'getState') await vault.touch();

  switch (request.type) {
    case 'getState': {
      const unlocked = await vault.isUnlocked();
      return ok<VaultState>({
        status: unlocked ? 'unlocked' : 'locked',
        email: (await vault.email()) ?? (await loadLastEmail(settingsStore)),
        settings: await loadSettings(settingsStore),
      });
    }
    case 'unlock':
      await vault.unlock(String(request.email ?? ''), String(request.password ?? ''));
      await saveLastEmail(settingsStore, String(request.email).trim().toLowerCase());
      await tabs.notifyUnlocked();
      return ok(null);
    case 'lock':
      await vault.lock();
      return ok(null);
    case 'listItems':
      return ok(await vault.listForPopup());
    case 'getMatchesForTab': {
      const url = await tabs.getUrl(request.tabId);
      return ok(url ? await vault.matchesForUrl(url) : []);
    }
    case 'fillTab': {
      const url = await tabs.getUrl(request.tabId);
      if (!url) throw new Error('Cannot fill this tab');
      const credential = await vault.credentialFor(request.itemId, url);
      await tabs.sendFill(request.tabId, { type: 'fillCredential', ...credential });
      return ok(null);
    }
    case 'scheduleClipboardClear':
      await deps.clipboard.scheduleClear();
      return ok(null);
    case 'saveSettings': {
      const previous = await loadSettings(settingsStore);
      const settings = await saveSettings(settingsStore, request.settings);
      // A session belongs to one server; switching servers locks.
      if (settings.serverUrl !== previous.serverUrl) await vault.lock();
      return ok(settings);
    }
  }
}

async function handleContent(
  request: ContentRequest,
  sender: Extract<Sender, { kind: 'content' }>,
  deps: RouterDeps,
): Promise<Response<unknown>> {
  const { vault } = deps;
  switch (request.type) {
    case 'getMatches':
      if (!(await vault.isUnlocked())) return { ok: false, error: 'Vault is locked', locked: true };
      return ok(await vault.matchesForUrl(sender.url));
    case 'fill': {
      // Only reached from a trusted click on our in-page prompt; counts as activity.
      await vault.touch();
      return ok(await vault.credentialFor(String(request.itemId), sender.url));
    }
    case 'captureCredential':
      await vault.captureCredential(
        sender.tabId,
        sender.url,
        String(request.username ?? ''),
        String(request.password ?? ''),
      );
      return ok(null);
    case 'getPendingSave':
      return ok(await vault.pendingSavePrompt(sender.tabId));
    case 'resolvePendingSave':
      await vault.touch();
      await vault.resolvePendingSave(sender.tabId, request.save === true);
      return ok(null);
  }
}
