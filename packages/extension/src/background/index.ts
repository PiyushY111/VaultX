import type { FillCredentialMessage } from '../shared/messages';
import { classifySender, handleMessage, type RouterDeps } from './router';
import { loadSettings } from './settings';
import { chromeStore } from './storage';
import { Vault } from './vault';

const AUTO_LOCK_ALARM = 'auto-lock';

const sessionStore = chromeStore(chrome.storage.session);
const settingsStore = chromeStore(chrome.storage.local);

const vault = new Vault({
  session: sessionStore,
  fetch: (input, init) => fetch(input, init),
  now: () => Date.now(),
  getSettings: () => loadSettings(settingsStore),
});

const deps: RouterDeps = {
  vault,
  settingsStore,
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
    async notifyUnlocked() {
      const tabs = await chrome.tabs.query({
        url: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'],
      });
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
