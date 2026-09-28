// The same generator as the web vault (one implementation to review).
import {
  DEFAULT_GENERATOR_OPTIONS,
  generatePassword,
} from '../../../web/src/lib/passwordGenerator';
import { emblem, keyhole } from '../shared/emblem';
import type {
  CheckpointInfo,
  CheckpointVerification,
  ItemSummary,
  PendingBaselineInfo,
  PopupItem,
  PopupRequest,
  Response,
  Settings,
  TotpCodeResponse,
  VaultState,
  VaultWarnings,
} from '../shared/messages';

// The popup is a trusted extension page, but item fields (e.g. a site name
// captured from a web page) are still untrusted strings: everything is
// rendered with textContent, never innerHTML.

const AUTO_LOCK_OPTIONS_MINUTES = [5, 15, 30, 60];
const app = document.getElementById('app')!;

class RequestError extends Error {
  constructor(
    message: string,
    readonly locked: boolean,
    /** The password was right and a two-factor code is needed next. */
    readonly secondFactor = false,
    /** ...and it has to be a passkey or recovery code (the extension can't use passkeys). */
    readonly passkeyOnly = false,
  ) {
    super(message);
  }
}

async function send<T>(request: PopupRequest): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T>;
  if (!response.ok) {
    throw new RequestError(
      response.error,
      response.locked === true,
      response.secondFactor === true,
      response.passkeyOnly === true,
    );
  }
  return response.data;
}

type Child = Node | string | null | undefined | false;

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, string | boolean | ((event: Event) => void)>> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === 'function')
      element.addEventListener(key.replace(/^on/, '').toLowerCase(), value);
    else if (typeof value === 'boolean') element.toggleAttribute(key, value);
    else if (value !== undefined) element.setAttribute(key, value);
  }
  for (const child of children) {
    if (child) element.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return element;
}

function mount(...children: Child[]): void {
  app.replaceChildren(...children.filter((child): child is Node | string => Boolean(child)));
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong';
}

async function activeTabId(): Promise<number | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id !== undefined && /^https?:/.test(tab.url ?? '') ? tab.id : null;
}

/** Hostname of the active http(s) tab, to prefill a new login's site. */
async function activeTabHost(): Promise<string> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    const url = new URL(tab?.url ?? '');
    return /^https?:$/.test(url.protocol) ? url.hostname.replace(/^www\./, '') : '';
  } catch {
    return '';
  }
}

async function render(): Promise<void> {
  const state = await send<VaultState>({ type: 'getState' });
  if (state.status === 'unlocked') await renderVault(state);
  else renderUnlock(state);
}

function onRequestError(error: unknown, show: (message: string) => void): void {
  if (error instanceof RequestError && error.locked) void render();
  else show(errorText(error));
}

// --- Unlock ------------------------------------------------------------------

function renderUnlock(state: VaultState, message?: string): void {
  const email = h('input', {
    type: 'email',
    name: 'email',
    required: true,
    autocomplete: 'username',
  });
  email.value = state.email ?? '';
  const password = h('input', {
    type: 'password',
    name: 'password',
    required: true,
    autocomplete: 'current-password',
  });
  const error = h('p', { class: 'error', role: 'alert' }, message);
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Unlock');

  const form = h(
    'form',
    {
      'aria-label': 'Unlock vault',
      onsubmit: async (event: Event) => {
        event.preventDefault();
        const submitted = password.value;
        password.value = '';
        submit.disabled = true;
        submit.textContent = 'Deriving keys…';
        error.textContent = '';
        try {
          await send({ type: 'unlock', email: email.value, password: submitted });
          await render();
        } catch (err) {
          if (err instanceof RequestError && err.secondFactor) {
            renderSecondFactor(state, err.passkeyOnly);
            return;
          }
          error.textContent = errorText(err);
          submit.disabled = false;
          submit.textContent = 'Unlock';
          password.focus();
        }
      },
    },
    h('label', {}, 'Email', email),
    h('label', {}, 'Master password', password),
    error,
    submit,
  );

  mount(
    // The storehouse wall (decorative): the emblem and the "Locked" stamp.
    h(
      'div',
      { class: 'wall', 'aria-hidden': 'true' },
      emblem('wall-mark'),
      h('span', { class: 'stamp' }, 'Locked'),
    ),
    h(
      'div',
      { class: 'panel' },
      h(
        'div',
        { class: 'row' },
        h('h1', { class: 'brand' }, 'VaultX'),
        h('span', { class: 'spacer' }),
        settingsButton(state),
      ),
      h('h2', { class: 'title' }, 'Vault locked'),
      form,
      h('p', { class: 'muted server' }, `Server: ${state.settings.serverUrl}`),
      h('p', { class: 'muted' }, 'No account? Create one in the web vault.'),
    ),
  );
  (state.email ? password : email).focus();
}

/**
 * The second step of unlocking when the account has two-factor login on.
 * Passkeys can't be used from the extension (WebAuthn from an extension
 * popup is unreliable, and passkeys are bound to the web vault's origin),
 * so a passkey-only account is told to use the web vault, and can still
 * unlock here with a recovery code.
 */
function renderSecondFactor(state: VaultState, passkeyOnly = false): void {
  let recovery = passkeyOnly;
  const code = h('input', {
    name: 'code',
    required: true,
    autocomplete: 'one-time-code',
    inputmode: recovery ? 'text' : 'numeric',
  });
  const label = h('label', {}, recovery ? 'Recovery code' : 'Authentication code', code);
  const hint = h(
    'p',
    { class: 'muted' },
    recovery
      ? 'Enter one of your recovery codes. Each one works once.'
      : 'Enter the 6-digit code from your authenticator app.',
  );
  const passkeyNotice =
    passkeyOnly &&
    h(
      'p',
      { class: 'notice', role: 'status' },
      'This account signs in with a passkey, and passkeys don’t work in the extension. Log in with your passkey in the web vault instead, or use a recovery code here.',
    );
  const error = h('p', { class: 'error', role: 'alert' });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Verify');
  const toggle = h(
    'button',
    {
      type: 'button',
      class: 'btn btn-quiet',
      onclick: () => {
        recovery = !recovery;
        label.firstChild!.textContent = recovery ? 'Recovery code' : 'Authentication code';
        hint.textContent = recovery
          ? 'Enter one of your recovery codes. Each one works once.'
          : 'Enter the 6-digit code from your authenticator app.';
        code.setAttribute('inputmode', recovery ? 'text' : 'numeric');
        toggle.textContent = recovery ? 'Use my authenticator app' : 'Use a recovery code';
        code.value = '';
        code.focus();
      },
    },
    'Use a recovery code',
  );

  mount(
    h('header', { class: 'topbar' }, emblem('mark'), h('h1', { class: 'brand' }, 'VaultX')),
    h(
      'form',
      {
        class: 'panel',
        'aria-label': 'Two-factor code',
        onsubmit: async (event: Event) => {
          event.preventDefault();
          submit.disabled = true;
          submit.textContent = 'Checking…';
          error.textContent = '';
          try {
            await send({ type: 'unlockSecondFactor', code: code.value, recovery });
            await render();
          } catch (err) {
            error.textContent = errorText(err);
            submit.disabled = false;
            submit.textContent = 'Verify';
            code.value = '';
            code.focus();
          }
        },
      },
      h('h2', { class: 'title' }, passkeyOnly ? 'Passkey required' : 'Two-factor code'),
      passkeyNotice,
      hint,
      label,
      error,
      h(
        'div',
        { class: 'row' },
        submit,
        // With a passkey-only account there's nothing to toggle to.
        !passkeyOnly && toggle,
        h(
          'button',
          { type: 'button', class: 'btn btn-quiet', onclick: () => renderUnlock(state) },
          'Cancel',
        ),
      ),
    ),
  );
  code.focus();
}

/** One line per kind of problem the vault's integrity checks found. */
function warningMessages(w: VaultWarnings): string[] {
  const messages: string[] = [];
  if (w.failed)
    messages.push(`${w.failed} login(s) couldn’t be decrypted and may have been tampered with.`);
  if (w.rolledBack)
    messages.push(
      `${w.rolledBack} login(s) are older than a version already seen, so they’re hidden.`,
    );
  if (w.missing)
    messages.push(`${w.missing} login(s) in your vault weren’t returned by the server.`);
  if (w.unexpected)
    messages.push(
      `${w.unexpected} login(s) returned by the server aren’t part of your vault, so they’re hidden.`,
    );
  if (w.manifest === 'tampered')
    messages.push('Your vault’s item list failed its integrity check.');
  if (w.manifest === 'stale')
    messages.push('The server returned an older copy of your vault than this browser has seen.');
  if (w.manifest === 'missing') messages.push('Your vault’s item list is missing from the server.');
  return messages;
}

// --- Vault -------------------------------------------------------------------

async function renderVault(state: VaultState): Promise<void> {
  const status = h('p', { class: 'error', role: 'alert' });
  const warnings = h('div', { class: 'warnings', role: 'alert', 'aria-label': 'Vault warnings' });
  warnings.hidden = true;
  const search = h('input', {
    type: 'search',
    class: 'search',
    placeholder: 'Search site, username or notes',
    'aria-label': 'Search vault',
  });
  const list = h('ul', { class: 'ledger', 'aria-label': 'All logins' });
  const matchesSection = h('section', { class: 'this-site', 'aria-label': 'Logins for this site' });
  matchesSection.hidden = true;
  const baselineBox = h('section', { class: 'warnings', 'aria-label': 'Confirm this vault' });
  baselineBox.hidden = true;
  const addButton = h(
    'button',
    {
      type: 'button',
      class: 'btn btn-primary',
      onclick: async () => renderAddItem(state, await activeTabHost()),
    },
    'Add login',
  );

  mount(
    h(
      'header',
      { class: 'topbar' },
      emblem('mark'),
      h('h1', { class: 'brand' }, 'VaultX'),
      h('span', { class: 'spacer' }),
      settingsButton(state),
      h(
        'button',
        {
          type: 'button',
          class: 'btn btn-seal',
          onclick: async () => {
            await send({ type: 'lock' });
            await render();
          },
        },
        h('span', { class: 'btn-seal-glyph' }, keyhole('btn-seal-icon')),
        'Lock',
      ),
    ),
    h(
      'div',
      { class: 'panel' },
      h('p', { class: 'muted' }, `Unlocked as ${state.email ?? ''}`),
      warnings,
      baselineBox,
      status,
      matchesSection,
      h(
        'div',
        { class: 'row' },
        h('h2', { class: 'section-title' }, 'All logins'),
        h('span', { class: 'spacer' }),
        addButton,
      ),
      search,
      list,
      checkpointSection(),
    ),
  );

  let items: PopupItem[];
  try {
    items = await send<PopupItem[]>({ type: 'listItems' });
    const baseline = await send<PendingBaselineInfo | null>({ type: 'getBaseline' });
    if (baseline) {
      addButton.disabled = true;
      showBaseline(baselineBox, baseline);
    }
    const messages = warningMessages(await send<VaultWarnings>({ type: 'getWarnings' }));
    if (messages.length) {
      warnings.hidden = false;
      warnings.replaceChildren(
        h('strong', {}, 'Your vault may have been tampered with'),
        ...messages.map((message) => h('p', {}, message)),
      );
    }
  } catch (error) {
    onRequestError(error, (message) => (status.textContent = message));
    return;
  }

  // Search runs over decrypted items in this page's memory only.
  const renderList = () => {
    const query = search.value.trim().toLowerCase();
    const visible = items.filter((item) =>
      [item.site, item.username, item.notes].some((value) => value.toLowerCase().includes(query)),
    );
    list.replaceChildren(
      ...(visible.length
        ? visible.map((item) => itemRow(item, status))
        : [
            h(
              'li',
              { class: 'empty' },
              items.length
                ? 'No logins match your search.'
                : 'Your vault is empty. Add a login, or save them as you sign in.',
            ),
          ]),
    );
  };
  search.addEventListener('input', renderList);
  renderList();

  const tabId = await activeTabId();
  if (tabId !== null) {
    try {
      const matches = await send<ItemSummary[]>({ type: 'getMatchesForTab', tabId });
      if (matches.length) {
        matchesSection.hidden = false;
        matchesSection.append(
          h('h2', { class: 'section-title' }, 'This site'),
          ...matches.map((match) =>
            h(
              'div',
              { class: 'match' },
              h('span', { class: 'match-user' }, match.username || '(no username)'),
              h(
                'button',
                {
                  type: 'button',
                  class: 'btn btn-primary',
                  onclick: async () => {
                    try {
                      await send({ type: 'fillTab', tabId, itemId: match.id });
                      window.close();
                    } catch (error) {
                      onRequestError(error, (message) => (status.textContent = message));
                    }
                  },
                },
                'Fill',
              ),
            ),
          ),
        );
      }
    } catch (error) {
      onRequestError(error, (message) => (status.textContent = message));
    }
  }
}

/** Six digits in two groups, as authenticator apps show them. */
const groupDigits = (code: string) => code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2');

/**
 * The item's current two-factor code, refreshed as each one expires. The
 * background computes it; the secret itself never reaches the popup.
 */
function totpLine(
  item: PopupItem,
  status: HTMLElement,
  copy: (value: string, button: HTMLButtonElement, secret: boolean) => Promise<void>,
): HTMLElement {
  const code = h('code', { class: 'totp-code', 'aria-label': 'Two-factor code' }, '••• •••');
  const left = h('span', { class: 'muted totp-left' });
  let current = '';
  const button = h(
    'button',
    { type: 'button', class: 'btn btn-quiet', 'data-label': 'Copy code' },
    'Copy code',
  );
  button.addEventListener('click', () => void (current && copy(current, button, true)));
  const line = h('div', { class: 'totp' }, code, left, button);

  let expiresAt = 0;
  const refresh = async () => {
    if (!line.isConnected && current) return; // Row was replaced (e.g. by a search).
    try {
      const next = await send<TotpCodeResponse>({ type: 'getTotpCode', itemId: item.id });
      current = next.code;
      code.textContent = groupDigits(next.code);
      expiresAt = Date.now() + next.secondsLeft * 1000;
    } catch (error) {
      onRequestError(error, (message) => (status.textContent = message));
      return;
    }
    tick();
  };
  const tick = () => {
    if (!line.isConnected && current) return;
    const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    left.textContent = `${seconds}s`;
    if (seconds === 0) void refresh();
    else setTimeout(tick, 1000);
  };
  void refresh();
  return line;
}

function itemRow(item: PopupItem, status: HTMLElement): HTMLLIElement {
  const secret = h('code', { class: 'secret' }, '••••••••');
  let revealed = false;
  const copy = async (value: string, button: HTMLButtonElement, secret = false) => {
    try {
      await navigator.clipboard.writeText(value);
      // The popup usually closes before 30 seconds pass, so the background clears it.
      if (secret) await send({ type: 'scheduleClipboardClear' });
      button.textContent = 'Copied';
      setTimeout(() => (button.textContent = button.dataset.label ?? 'Copy'), 1500);
    } catch {
      status.textContent = 'Could not copy to the clipboard';
    }
  };
  const copyUser = h(
    'button',
    { type: 'button', class: 'btn btn-quiet', 'data-label': 'Copy user' },
    'Copy user',
  );
  copyUser.addEventListener('click', () => void copy(item.username, copyUser));
  const copyPassword = h(
    'button',
    { type: 'button', class: 'btn btn-quiet', 'data-label': 'Copy password' },
    'Copy password',
  );
  copyPassword.addEventListener('click', () => void copy(item.password, copyPassword, true));
  copyPassword.title = 'Cleared from the clipboard after 30 seconds';

  return h(
    'li',
    { class: 'entry', 'aria-label': item.site },
    h('span', { class: 'initial', 'aria-hidden': 'true' }, crestLetter(item.site)),
    h(
      'div',
      { class: 'entry-body' },
      h('strong', { class: 'entry-site' }, item.site),
      item.username && h('span', { class: 'entry-user' }, item.username),
      secret,
      item.hasTotp && totpLine(item, status, copy),
    ),
    h(
      'div',
      { class: 'entry-actions' },
      h(
        'button',
        {
          type: 'button',
          class: 'btn btn-quiet',
          onclick: (event: Event) => {
            revealed = !revealed;
            secret.textContent = revealed ? item.password : '••••••••';
            secret.classList.toggle('is-revealed', revealed);
            (event.target as HTMLButtonElement).textContent = revealed ? 'Hide' : 'Show';
          },
        },
        'Show',
      ),
      copyUser,
      copyPassword,
    ),
  );
}

// --- Add login ---------------------------------------------------------------

function renderAddItem(state: VaultState, site: string): void {
  const siteInput = h('input', { name: 'site', required: true, autocomplete: 'off' });
  siteInput.value = site;
  const username = h('input', { name: 'username', autocomplete: 'off' });
  const password = h('input', {
    id: 'new-item-password',
    type: 'password',
    name: 'password',
    class: 'secret-input',
    autocomplete: 'new-password',
  });
  const notes = h('textarea', { name: 'notes', rows: '3' });
  const error = h('p', { class: 'error', role: 'alert' });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save');

  const toggle = h(
    'button',
    {
      type: 'button',
      class: 'btn btn-quiet',
      onclick: () => {
        const show = password.type === 'password';
        password.type = show ? 'text' : 'password';
        toggle.textContent = show ? 'Hide' : 'Show';
      },
    },
    'Show',
  );
  const generate = h(
    'button',
    {
      type: 'button',
      class: 'btn',
      onclick: () => {
        password.value = generatePassword(DEFAULT_GENERATOR_OPTIONS);
        password.type = 'text';
        toggle.textContent = 'Hide';
      },
    },
    'Generate',
  );

  mount(
    h('header', { class: 'topbar' }, emblem('mark'), h('h1', { class: 'brand' }, 'Add login')),
    h(
      'form',
      {
        class: 'panel',
        'aria-label': 'Add login',
        onsubmit: async (event: Event) => {
          event.preventDefault();
          submit.disabled = true;
          submit.textContent = 'Encrypting…';
          error.textContent = '';
          try {
            await send({
              type: 'addItem',
              item: {
                site: siteInput.value,
                username: username.value,
                password: password.value,
                notes: notes.value,
              },
            });
            await render();
          } catch (err) {
            onRequestError(err, (message) => (error.textContent = message));
            submit.disabled = false;
            submit.textContent = 'Save';
          }
        },
      },
      h('label', {}, 'Site', siteInput),
      h('label', {}, 'Username', username),
      h(
        'div',
        { class: 'field' },
        h('label', { for: 'new-item-password' }, 'Password'),
        h('div', { class: 'row password-row' }, password, toggle, generate),
      ),
      h('label', {}, 'Notes', notes),
      h('p', { class: 'muted' }, 'Encrypted on this device before it’s sent to your server.'),
      error,
      h(
        'div',
        { class: 'row' },
        submit,
        h(
          'button',
          { type: 'button', class: 'btn btn-quiet', onclick: () => void renderVault(state) },
          'Cancel',
        ),
      ),
    ),
  );
  (site ? username : siteInput).focus();
}

/** First letter of the site's name, shown in a small crest. */
function crestLetter(site: string): string {
  const name = site.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '');
  return (name.match(/[\p{L}\p{N}]/u)?.[0] ?? '?').toUpperCase();
}

// --- Settings ----------------------------------------------------------------

function settingsButton(state: VaultState): HTMLButtonElement {
  return h(
    'button',
    { type: 'button', class: 'btn btn-quiet', onclick: () => renderSettings(state) },
    'Settings',
  );
}

const BASELINE_REASONS: Record<PendingBaselineInfo['reason'], string> = {
  none: 'This vault has no encrypted list of your items yet (it was created before VaultX kept one), so there’s nothing to check what the server sent against.',
  missing:
    'This browser has seen an encrypted list of your items before, but the server no longer has one. The server may have lost data, or be hiding changes.',
  tampered:
    'The server’s encrypted list of your items doesn’t open with your vault key, so it can’t be trusted.',
};

const formatDate = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/**
 * Asks before trusting a vault with no usable manifest (like the web vault).
 * Only this popup can accept; content scripts can't send acceptBaseline.
 */
function showBaseline(box: HTMLElement, baseline: PendingBaselineInfo): void {
  const { itemCount, oldestUpdate, newestUpdate, previouslySeenVersion, reason } = baseline;
  const error = h('p', { class: 'error', role: 'alert' });
  const declined = () =>
    box.replaceChildren(
      h('strong', {}, 'This vault isn’t confirmed yet, so it’s read-only.'),
      h('p', {}, 'Nothing can be saved to it until you confirm it.'),
      h(
        'button',
        { type: 'button', class: 'btn btn-quiet', onclick: () => showBaseline(box, baseline) },
        'Review',
      ),
    );
  box.hidden = false;
  box.replaceChildren(
    h('strong', {}, 'Use this as the trusted baseline?'),
    h('p', {}, BASELINE_REASONS[reason]),
    h(
      'p',
      {},
      `The server sent ${itemCount} item${itemCount === 1 ? '' : 's'} that opened with your key` +
        (oldestUpdate && newestUpdate
          ? `, last changed between ${formatDate(oldestUpdate)} and ${formatDate(newestUpdate)} (the server’s dates).`
          : '.') +
        (previouslySeenVersion > 0
          ? ` This browser had seen version ${previouslySeenVersion} of the list before.`
          : ''),
    ),
    h(
      'p',
      { class: 'muted' },
      'Confirm only if this looks like your whole vault. Otherwise choose “Not now” and check from another device (compare the vault checkpoint).',
    ),
    error,
    h(
      'div',
      { class: 'row' },
      h(
        'button',
        {
          type: 'button',
          class: 'btn btn-primary',
          onclick: async () => {
            try {
              await send({ type: 'acceptBaseline' });
              await render();
            } catch (err) {
              onRequestError(err, (message) => (error.textContent = message));
            }
          },
        },
        'Use as trusted baseline',
      ),
      h('button', { type: 'button', class: 'btn btn-quiet', onclick: declined }, 'Not now'),
    ),
  );
}

const CHECKPOINT_RESULTS: Record<
  CheckpointVerification['result'],
  (v: CheckpointVerification) => string
> = {
  match: (v) => `Match: this device sees the same vault (version ${v.currentVersion}).`,
  'older-checkpoint': (v) =>
    `That checkpoint is from an earlier version (${v.claimedVersion}); this device sees version ${v.currentVersion}. That’s expected if the vault has changed since.`,
  rollback: (v) =>
    `Warning: this device sees an older vault (version ${v.currentVersion}) than your checkpoint (version ${v.claimedVersion}). The server may be showing you an old copy.`,
  mismatch: (v) =>
    `Warning: same version (${v.currentVersion}), different fingerprint. This isn’t the vault your other device saw.`,
};

/** The vault checkpoint, and a box to check one copied from another device. */
function checkpointSection(): HTMLElement {
  const value = h('code', { class: 'checkpoint', 'aria-label': 'Vault checkpoint' }, '…');
  const input = h('input', {
    name: 'checkpoint',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: '42 · ABCD-EFGH-IJKL-MNOP',
  });
  const result = h('p', { class: 'muted', role: 'status' });
  const details = h(
    'details',
    { class: 'checkpoint-section' },
    h('summary', {}, 'Vault checkpoint'),
    h('p', {}, value),
    h(
      'p',
      { class: 'muted' },
      'Compare with the checkpoint on another device or your emergency kit. It’s computed with your vault key and means nothing to anyone else.',
    ),
    h(
      'form',
      {
        'aria-label': 'Verify checkpoint',
        onsubmit: async (event: Event) => {
          event.preventDefault();
          try {
            const verification = await send<CheckpointVerification>({
              type: 'verifyCheckpoint',
              checkpoint: input.value,
            });
            const bad = verification.result === 'rollback' || verification.result === 'mismatch';
            result.className = bad ? 'error' : 'muted';
            result.setAttribute('role', bad ? 'alert' : 'status');
            result.textContent = CHECKPOINT_RESULTS[verification.result](verification);
          } catch (err) {
            result.className = 'error';
            result.setAttribute('role', 'alert');
            result.textContent = errorText(err);
          }
        },
      },
      h('label', {}, 'Checkpoint from another device', input),
      h('button', { type: 'submit', class: 'btn' }, 'Verify checkpoint'),
    ),
    result,
  );
  void send<CheckpointInfo>({ type: 'getCheckpoint' }).then(
    ({ checkpoint }) => (value.textContent = checkpoint ?? 'None yet: confirm your vault first.'),
    (err: unknown) => (value.textContent = errorText(err)),
  );
  return details;
}

function renderSettings(state: VaultState): void {
  const serverUrl = h('input', { type: 'url', name: 'serverUrl', required: true });
  serverUrl.value = state.settings.serverUrl;
  const autoLock = h(
    'select',
    { name: 'autoLockMinutes' },
    ...AUTO_LOCK_OPTIONS_MINUTES.map((minutes) => {
      const option = h('option', { value: String(minutes) }, `${minutes} minutes`);
      option.selected = minutes === state.settings.autoLockMinutes;
      return option;
    }),
  );
  const error = h('p', { class: 'error', role: 'alert' });

  mount(
    h('header', { class: 'topbar' }, emblem('mark'), h('h1', { class: 'brand' }, 'Settings')),
    h(
      'form',
      {
        class: 'panel',
        'aria-label': 'Settings',
        onsubmit: async (event: Event) => {
          event.preventDefault();
          try {
            const settings: Settings = {
              serverUrl: serverUrl.value,
              autoLockMinutes: Number(autoLock.value),
            };
            await send<Settings>({ type: 'saveSettings', settings });
            await render();
          } catch (err) {
            error.textContent = errorText(err);
          }
        },
      },
      h('label', {}, 'Server URL', serverUrl),
      h('p', { class: 'muted' }, 'Changing the server locks the vault.'),
      h('label', {}, 'Auto-lock after inactivity', autoLock),
      error,
      h(
        'div',
        { class: 'row' },
        h('button', { type: 'submit', class: 'btn btn-primary' }, 'Save'),
        h(
          'button',
          { type: 'button', class: 'btn btn-quiet', onclick: () => void render() },
          'Cancel',
        ),
      ),
    ),
  );
}

void render().catch((error: unknown) => mount(h('p', { class: 'error' }, errorText(error))));
