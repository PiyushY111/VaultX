import { emblem, keyhole } from '../shared/emblem';
import type {
  ItemSummary,
  PopupItem,
  PopupRequest,
  Response,
  Settings,
  VaultState,
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
  ) {
    super(message);
  }
}

async function send<T>(request: PopupRequest): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T>;
  if (!response.ok) throw new RequestError(response.error, response.locked === true);
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

// --- Vault -------------------------------------------------------------------

async function renderVault(state: VaultState): Promise<void> {
  const status = h('p', { class: 'error', role: 'alert' });
  const search = h('input', {
    type: 'search',
    class: 'search',
    placeholder: 'Search site, username or notes',
    'aria-label': 'Search vault',
  });
  const list = h('ul', { class: 'ledger', 'aria-label': 'All logins' });
  const matchesSection = h('section', { class: 'this-site', 'aria-label': 'Logins for this site' });
  matchesSection.hidden = true;

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
      status,
      matchesSection,
      h('h2', { class: 'section-title' }, 'All logins'),
      search,
      list,
    ),
  );

  let items: PopupItem[];
  try {
    items = await send<PopupItem[]>({ type: 'listItems' });
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
                : 'Your vault is empty. Add logins in the web vault, or save them as you sign in.',
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
