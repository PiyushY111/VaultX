// The same generator as the web vault and the popup (one implementation to review).
import {
  DEFAULT_GENERATOR_OPTIONS,
  generatePassword,
} from '../../../web/src/lib/passwordGenerator';
import type { BackgroundToContent, FillCredentialMessage } from '../shared/messages';
import { clipboardClearer } from './clipboard';
import { MENU_ITEMS, handleFillCommand, handleMenuClick, type CommandDeps } from './commands';
import { classifySender, handleMessage, type RouterDeps } from './router';
import { loadSettings } from './settings';
import { chromeStore } from './storage';
import { Vault } from './vault';

const AUTO_LOCK_ALARM = 'auto-lock';
/** Where the content script runs, and so where filling (and the menu) can work. */
const PAGES = ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'];

const sessionStore = chromeStore(chrome.storage.session);
const settingsStore = chromeStore(chrome.storage.local);

const vault = new Vault({
  session: sessionStore,
  local: settingsStore,
  fetch: (input, init) => fetch(input, init),
  now: () => Date.now(),
  getSettings: () => loadSettings(settingsStore),
  onLock: () => clipboardClearer.clearIfPending(),
});

const deps: RouterDeps = {
  vault,
  settingsStore,
  clipboard: clipboardClearer,
  tabs: {
    async getUrl(tabId) {
      try {
        return (await chrome.tabs.get(tabId)).url;
      } catch {
        return undefined;
      }
    },
    async sendFill(tabId, message: FillCredentialMessage & { host: string }) {
      // Top frame only. The content script re-checks that its own hostname
      // still matches `host`, in case the tab navigated in between.
      await chrome.tabs.sendMessage(tabId, message, { frameId: 0 });
    },
    async sendFillForm(tabId, message) {
      // Top frame only; the content script re-checks `host`, like sendFill.
      await chrome.tabs.sendMessage(tabId, message, { frameId: 0 });
    },
    async notifyUnlocked() {
      const tabs = await chrome.tabs.query({ url: PAGES });
      await Promise.all(
        tabs.map((tab) =>
          tab.id === undefined
            ? undefined
            : chrome.tabs
                .sendMessage(tab.id, { type: 'vaultUnlocked' }, { frameId: 0 })
                .catch(() => undefined),
        ),
      );
    },
  },
};

const popupUrl = chrome.runtime.getURL('popup.html');

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, classifySender(sender, chrome.runtime.id, popupUrl), deps).then(
    sendResponse,
  );
  return true; // Respond asynchronously.
});

// Inactivity timeout: checked every 30s (the minimum alarm period) and on every message.
void chrome.alarms.create(AUTO_LOCK_ALARM, { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) void vault.enforceAutoLock();
  clipboardClearer.onAlarm(alarm);
});

// Lock immediately when the OS screen locks.
chrome.idle.onStateChanged.addListener((state) => {
  if (state === 'locked') void vault.lock();
});

// chrome.storage.session is already empty after a browser restart; clear
// explicitly anyway so a restart always means locked.
chrome.runtime.onStartup.addListener(() => {
  void vault.lock();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void vault.forgetTab(tabId);
});

// --- Keyboard shortcut and right-click menu (see commands.ts) ---------------

const sendToTab = async (tabId: number, message: BackgroundToContent) => {
  // Top frame only. A tab opened before the extension was installed has no
  // content script yet; there's nothing to tell it.
  await chrome.tabs.sendMessage(tabId, message, { frameId: 0 }).catch(() => undefined);
};

const commandDeps: CommandDeps = {
  vault,
  send: sendToTab,
  generatePassword: () => generatePassword(DEFAULT_GENERATOR_OPTIONS),
  // chrome.action.openPopup exists from Chrome 127; the manifest allows 120.
  ...(typeof chrome.action?.openPopup === 'function' && {
    openPopup: () => chrome.action.openPopup(),
  }),
};

/** A failure (e.g. the login went away meanwhile) is shown on the page, not dropped. */
function reportOn(tabId: number | undefined) {
  return (error: unknown) => {
    if (tabId === undefined) return;
    const message = error instanceof Error ? error.message : 'Something went wrong';
    void sendToTab(tabId, { type: 'showNotice', message: 'Could not fill', detail: message });
  };
}

chrome.commands.onCommand.addListener((command, tab) => {
  if (command === 'fill-login' && tab)
    void handleFillCommand(tab, commandDeps).catch(reportOn(tab.id));
});

// Menus persist across browser restarts; created once per install or update.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    const where = { contexts: ['editable'] as ['editable'], documentUrlPatterns: PAGES };
    chrome.contextMenus.create({ id: 'vaultx', title: 'VaultX', ...where });
    for (const item of MENU_ITEMS) {
      chrome.contextMenus.create({ id: item.id, parentId: 'vaultx', title: item.title, ...where });
    }
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  void handleMenuClick(String(info.menuItemId), info.frameId, tab ?? {}, commandDeps).catch(
    reportOn(tab?.id),
  );
});
