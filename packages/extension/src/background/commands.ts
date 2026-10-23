/**
 * The keyboard shortcut and the right-click menu. Both are browser UI: a
 * page can't press an extension's shortcut or click its menu entries, so
 * they count as the user's own choice, like a click on our prompt. That's
 * why a single match is filled straight away; with several, the page shows
 * our chooser (and the user picks there).
 *
 * Everything uses the browser-reported tab URL, never anything from the page.
 */
import type { BackgroundToContent, ChooserKind, FormKind } from '../shared/messages';
import { securePageHost } from '../shared/urls';
import type { Vault } from './vault';

/** The parts of a chrome.tabs.Tab used here (either may be missing). */
export interface CommandTab {
  id?: number | undefined;
  url?: string | undefined;
}

export interface CommandDeps {
  vault: Vault;
  /** Sends to the tab's top frame. */
  send(tabId: number, message: BackgroundToContent): Promise<void>;
  generatePassword(): string;
  /** chrome.action.openPopup, where the browser has it (Chrome 127+). */
  openPopup?: () => Promise<void>;
}

/** The right-click menu: entry ids → what they do. */
export const MENU_ITEMS = [
  { id: 'fill-login', title: 'Fill login' },
  { id: 'fill-totp', title: 'Fill two-factor code' },
  { id: 'fill-card', title: 'Fill card' },
  { id: 'fill-identity', title: 'Fill address' },
  { id: 'generate', title: 'Generate password' },
] as const;

export type MenuItemId = (typeof MENU_ITEMS)[number]['id'];

const notice = (message: string, detail?: string): BackgroundToContent => ({
  type: 'showNotice',
  message,
  ...(detail && { detail }),
});

const NONE: Record<ChooserKind, string> = {
  login: 'No saved login for this site',
  totp: 'No two-factor code saved for this site',
  card: 'No saved cards',
  identity: 'No saved addresses',
};

/** The tab, if it's a secure web page we may fill (the content script runs only there). */
function fillableTab(tab: CommandTab): { tabId: number; url: string; host: string } | null {
  if (tab.id === undefined || !tab.url) return null;
  const host = securePageHost(tab.url);
  return host ? { tabId: tab.id, url: tab.url, host } : null;
}

/**
 * Fills `kind` for the tab: the only match straight away, the chooser for
 * several, a notice for none. Locked: the popup opens to unlock, where it
 * can; otherwise the page says so.
 */
async function fill(
  kind: ChooserKind,
  target: { tabId: number; url: string },
  deps: CommandDeps,
): Promise<void> {
  const { vault, send } = deps;
  const { tabId, url } = target;
  if (!(await vault.isUnlocked())) {
    try {
      if (deps.openPopup) return await deps.openPopup();
    } catch {
      // The browser wouldn't open it (e.g. no focused window): say so on the page instead.
    }
    return send(tabId, notice('VaultX is locked', 'Click the extension icon and unlock.'));
  }
  await vault.touch();

  if (kind === 'login' || kind === 'totp') {
    const matches =
      kind === 'login' ? await vault.matchesForUrl(url) : await vault.totpMatchesForUrl(url);
    if (matches.length === 0) return send(tabId, notice(NONE[kind]));
    if (matches.length > 1) return send(tabId, { type: 'showChooser', kind });
    const itemId = matches[0]!.id;
    if (kind === 'totp') {
      const { code } = await vault.totpCodeForUrl(itemId, url);
      return send(tabId, { type: 'fillTotpCode', code, host: securePageHost(url)! });
    }
    const credential = await vault.credentialFor(itemId, url);
    return send(tabId, { type: 'fillCredential', ...credential });
  }

  const items = await vault.formItemSummaries(kind as FormKind, url);
  if (items.length === 0) return send(tabId, notice(NONE[kind]));
  if (items.length > 1) return send(tabId, { type: 'showChooser', kind });
  const fill = await vault.formFillFor(items[0]!.id, url, kind as FormKind);
  return send(tabId, { type: 'fillForm', ...fill });
}

/** The "Fill login" keyboard shortcut (Ctrl/⌘+Shift+L by default). */
export async function handleFillCommand(tab: CommandTab, deps: CommandDeps): Promise<void> {
  const target = fillableTab(tab);
  if (target) await fill('login', target, deps);
}

const MENU_KINDS: Partial<Record<string, ChooserKind>> = {
  'fill-login': 'login',
  'fill-totp': 'totp',
  'fill-card': 'card',
  'fill-identity': 'identity',
};

/**
 * A right-click menu entry. Only in the top frame: the content script (and so
 * the field that was right-clicked) isn't in embedded frames.
 */
export async function handleMenuClick(
  menuItemId: string,
  frameId: number | undefined,
  tab: CommandTab,
  deps: CommandDeps,
): Promise<void> {
  const target = fillableTab(tab);
  const kind = MENU_KINDS[menuItemId];
  if (!target || (!kind && menuItemId !== 'generate')) return;
  if (frameId !== 0) {
    return deps.send(target.tabId, notice('VaultX can’t fill inside embedded frames'));
  }
  if (kind) return fill(kind, target, deps);

  // Generating needs no vault, so it works while locked too.
  const password = deps.generatePassword();
  await deps.vault.rememberGenerated(target.tabId, target.host, password);
  await deps.send(target.tabId, { type: 'fillGenerated', password, host: target.host });
}
