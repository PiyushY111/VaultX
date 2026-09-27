/**
 * Message protocol between the popup, content scripts and the background
 * service worker. The background decides what each sender may do from the
 * browser-provided `sender`, never from anything inside the message.
 */

export interface Settings {
  serverUrl: string;
  autoLockMinutes: number;
}

export interface ItemSummary {
  id: string;
  site: string;
  username: string;
}

/** Full item, only ever sent to the popup (a trusted extension page). */
export interface PopupItem extends ItemSummary {
  password: string;
  notes: string;
}

export interface VaultState {
  status: 'locked' | 'unlocked';
  email: string | null;
  settings: Settings;
}

export interface PendingSavePrompt {
  kind: 'new' | 'update';
  host: string;
  username: string;
}

/** Requests only the popup may make. */
export type PopupRequest =
  | { type: 'getState' }
  | { type: 'unlock'; email: string; password: string }
  | { type: 'lock' }
  | { type: 'listItems' }
  | { type: 'getMatchesForTab'; tabId: number }
  | { type: 'fillTab'; tabId: number; itemId: string }
  | { type: 'saveSettings'; settings: Settings }
  /** Sent after the popup copies a password, so the background can clear it later. */
  | { type: 'scheduleClipboardClear' };

/** Requests only a content script (top frame of an http(s) tab) may make. */
export type ContentRequest =
  | { type: 'getMatches' }
  | { type: 'fill'; itemId: string }
  | { type: 'captureCredential'; username: string; password: string }
  | { type: 'getPendingSave' }
  | { type: 'resolvePendingSave'; save: boolean };

/** Sent by the background to a tab's content script. */
export interface FillCredentialMessage {
  type: 'fillCredential';
  username: string;
  password: string;
}

/** Sent by the background to its offscreen document. */
export interface ClearClipboardMessage {
  target: 'offscreen';
  type: 'clearClipboard';
}

/** Broadcast by the background after the vault unlocks. Carries no data. */
export interface VaultUnlockedMessage {
  type: 'vaultUnlocked';
}

export type Response<T> = { ok: true; data: T } | { ok: false; error: string; locked?: boolean };

export const POPUP_REQUEST_TYPES = new Set<PopupRequest['type']>([
  'getState',
  'unlock',
  'lock',
  'listItems',
  'getMatchesForTab',
  'fillTab',
  'saveSettings',
  'scheduleClipboardClear',
]);

export const CONTENT_REQUEST_TYPES = new Set<ContentRequest['type']>([
  'getMatches',
  'fill',
  'captureCredential',
  'getPendingSave',
  'resolvePendingSave',
]);
