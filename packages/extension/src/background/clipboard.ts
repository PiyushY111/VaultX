import type { ClearClipboardMessage } from '../shared/messages';

/**
 * Clears a password the popup copied, 30 seconds later (the popup itself is
 * usually closed by then) or as soon as the vault locks.
 *
 * The pending clear is a chrome.alarms alarm, so it survives the service
 * worker being stopped. The clipboard can't be read without an extra
 * permission, so the clear is unconditional: it may wipe something copied
 * since.
 */

const CLEAR_ALARM = 'clear-clipboard';
export const CLIPBOARD_CLEAR_MS = 30_000;

async function writeEmptyClipboard(): Promise<void> {
  if (!(await chrome.offscreen.hasDocument())) {
    await chrome.offscreen.createDocument({
      url: 'offscreen.html',
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: 'Clear a copied password from the clipboard',
    });
  }
  try {
    await chrome.runtime.sendMessage({
      target: 'offscreen',
      type: 'clearClipboard',
    } satisfies ClearClipboardMessage);
  } finally {
    await chrome.offscreen.closeDocument();
  }
}

async function clearNow(): Promise<void> {
  await chrome.alarms.clear(CLEAR_ALARM);
  await writeEmptyClipboard();
}

export const clipboardClearer = {
  async scheduleClear(): Promise<void> {
    await chrome.alarms.create(CLEAR_ALARM, { when: Date.now() + CLIPBOARD_CLEAR_MS });
  },
  /** Clears now if a copied password is still waiting to be cleared. */
  async clearIfPending(): Promise<void> {
    if (await chrome.alarms.get(CLEAR_ALARM)) await clearNow();
  },
  onAlarm(alarm: chrome.alarms.Alarm): void {
    if (alarm.name === CLEAR_ALARM) void clearNow();
  },
};
