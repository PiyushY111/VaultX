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

/** A login typed into the popup's "Add login" form. */
export interface NewItem {
  site: string;
  username: string;
  password: string;
  notes: string;
}

/** Full item, only ever sent to the popup (a trusted extension page). */
export interface PopupItem extends ItemSummary {
  password: string;
  notes: string;
  /** Has a two-factor secret; the popup asks for its current code with getTotpCode. */
  hasTotp: boolean;
}

export type FormKind = 'card' | 'identity';

/**
 * A card or identity as offered on a page or listed in the popup: a label
 * ("Visa •••• 4242 · Jane D.", "Home · Jane"), never its number, expiry,
 * security code or address.
 */
export interface FormItemSummary {
  id: string;
  label: string;
}

/** A card's or identity's fields, released for one page after a click. */
export interface FormFill {
  kind: FormKind;
  /** The page's host when released, so the content script can re-check it. */
  host: string;
  values: Record<string, string>;
}

/** A two-factor code, never the secret it comes from. */
export interface TotpCodeResponse {
  code: string;
  secondsLeft: number;
}

export interface VaultState {
  status: 'locked' | 'unlocked';
  email: string | null;
  settings: Settings;
}

/** A vault with no manifest the extension can trust (see the web vault's sync.ts). */
export interface PendingBaselineInfo {
  reason: 'none' | 'missing' | 'tampered';
  itemCount: number;
  oldestUpdate: string | null;
  newestUpdate: string | null;
  previouslySeenVersion: number;
}

/** The vault checkpoint, formatted ("42 · ABCD-EFGH-IJKL-MNOP"); null until there's a trusted manifest. */
export interface CheckpointInfo {
  checkpoint: string | null;
}

export interface CheckpointVerification {
  result: 'match' | 'mismatch' | 'rollback' | 'older-checkpoint';
  currentVersion: number;
  claimedVersion: number;
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
  | { type: 'addItem'; item: NewItem }
  /** The second step of unlocking, when the account has two-factor login on. */
  | { type: 'unlockSecondFactor'; code: string; recovery: boolean }
  | { type: 'getWarnings' }
  | { type: 'getTotpCode'; itemId: string }
  /** Sent after the popup copies a password, so the background can clear it later. */
  | { type: 'scheduleClipboardClear' }
  /** The vault has no trusted manifest yet: what would become the baseline. */
  | { type: 'getBaseline' }
  /** The user accepted it, in the popup. Content scripts can never send this. */
  | { type: 'acceptBaseline' }
  | { type: 'getCheckpoint' }
  | { type: 'verifyCheckpoint'; checkpoint: string }
  /** Cards and identities, as labels. */
  | { type: 'listFormItems' }
  /** One card's or identity's fields, to copy from the popup. */
  | { type: 'getFormItemFields'; itemId: string }
  /** Fills a card or identity into the active tab's form. */
  | { type: 'fillTabWithForm'; tabId: number; itemId: string }
  /** The password last generated for a tab from the right-click menu, if still kept. */
  | { type: 'getGenerated'; tabId: number };

/** Requests only a content script (top frame of an http(s) tab) may make. */
export type ContentRequest =
  | { type: 'getMatches' }
  | { type: 'fill'; itemId: string }
  | { type: 'captureCredential'; username: string; password: string }
  | { type: 'getPendingSave' }
  | { type: 'resolvePendingSave'; save: boolean }
  /** Logins for this page that have a two-factor secret (usernames only). */
  | { type: 'getTotpMatches' }
  /** The current code for one of them; only after a click on our prompt. */
  | { type: 'fillTotp'; itemId: string }
  /** Cards or identities to offer on a checkout or address form (labels only). */
  | { type: 'getFormItems'; kind: FormKind }
  /** One of them, to fill; only after a click on our prompt. */
  | { type: 'fillFormItem'; kind: FormKind; itemId: string };

/** Sent by the background to a tab's content script. */
export interface FillCredentialMessage {
  type: 'fillCredential';
  username: string;
  password: string;
}

/** A password generated from the right-click menu, kept so it can't be lost before it's saved. */
export interface GeneratedPassword {
  host: string;
  password: string;
  /** Epoch milliseconds. */
  createdAt: number;
}

/** What a keyboard shortcut or menu entry asks a page to offer, in our prompt. */
export type ChooserKind = 'login' | 'totp' | FormKind;

/** Sent by the background to a tab's content script, from the popup's "Fill in this tab". */
export interface FillFormMessage extends FormFill {
  type: 'fillForm';
}

/**
 * Everything the background sends a tab's content script (top frame only).
 * Anything carrying a value names the page `host` it was released for, and
 * the content script re-checks it before using the value.
 */
export type BackgroundToContent =
  | (FillCredentialMessage & { host: string })
  | FillFormMessage
  | VaultUnlockedMessage
  /** The user asked (shortcut or menu) and there are several items: show our chooser. */
  | { type: 'showChooser'; kind: ChooserKind }
  | { type: 'showNotice'; message: string; detail?: string }
  /** A generated password, for the right-clicked field (and its confirmation field). */
  | { type: 'fillGenerated'; password: string; host: string }
  | { type: 'fillTotpCode'; code: string; host: string };

/** Sent by the background to its offscreen document. */
export interface ClearClipboardMessage {
  target: 'offscreen';
  type: 'clearClipboard';
}

/** Broadcast by the background after the vault unlocks. Carries no data. */
export interface VaultUnlockedMessage {
  type: 'vaultUnlocked';
}

export type Response<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: string;
      locked?: boolean;
      /** The password was right; send a two-factor code with unlockSecondFactor. */
      secondFactor?: boolean;
      /**
       * The account needs a passkey (or a recovery code). Passkeys don't
       * work from the extension, so the popup points to the web vault.
       */
      passkeyOnly?: boolean;
    };

/** What the vault's integrity checks found on the last load. All zero for an honest server. */
export interface VaultWarnings {
  /** Failed to decrypt: tampered, corrupted, or moved to another id or revision. */
  failed: number;
  /** Older than a revision seen before, or not the revision the manifest lists. */
  rolledBack: number;
  /** Listed in the manifest but not returned by the server. */
  missing: number;
  /** Returned by the server but not in the manifest (e.g. deleted items brought back). */
  unexpected: number;
  manifest: 'tampered' | 'stale' | 'missing' | null;
}

export const POPUP_REQUEST_TYPES = new Set<PopupRequest['type']>([
  'getState',
  'unlock',
  'lock',
  'listItems',
  'getMatchesForTab',
  'fillTab',
  'saveSettings',
  'addItem',
  'unlockSecondFactor',
  'getWarnings',
  'getTotpCode',
  'scheduleClipboardClear',
  'getBaseline',
  'acceptBaseline',
  'getCheckpoint',
  'verifyCheckpoint',
  'listFormItems',
  'getFormItemFields',
  'fillTabWithForm',
  'getGenerated',
]);

export const CONTENT_REQUEST_TYPES = new Set<ContentRequest['type']>([
  'getMatches',
  'fill',
  'captureCredential',
  'getPendingSave',
  'resolvePendingSave',
  'getTotpMatches',
  'fillTotp',
  'getFormItems',
  'fillFormItem',
]);
