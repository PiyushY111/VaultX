import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  classifySender,
  handleMessage,
  type RouterDeps,
  type Sender,
} from '../src/background/router';
import { DEFAULT_SETTINGS } from '../src/background/settings';
import { Vault } from '../src/background/vault';
import { CONTENT_REQUEST_TYPES, POPUP_REQUEST_TYPES } from '../src/shared/messages';
import { MemoryStore, SERVER, createFakeServer } from './helpers';

const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop';
const POPUP_URL = `chrome-extension://${EXTENSION_ID}/popup.html`;

describe('classifySender', () => {
  it('recognizes our popup', () => {
    expect(classifySender({ id: EXTENSION_ID, url: POPUP_URL }, EXTENSION_ID, POPUP_URL)).toEqual({
      kind: 'popup',
    });
  });

  it('recognizes our content script in a top frame, using the browser-reported URL', () => {
    const sender = {
      id: EXTENSION_ID,
      url: 'https://github.com/login',
      frameId: 0,
      tab: { id: 5 } as chrome.tabs.Tab,
    };
    expect(classifySender(sender, EXTENSION_ID, POPUP_URL)).toEqual({
      kind: 'content',
      tabId: 5,
      url: 'https://github.com/login',
    });
  });

  it.each([
    ['another extension', { id: 'other', url: POPUP_URL }],
    [
      'a subframe',
      {
        id: EXTENSION_ID,
        url: 'https://github.com/',
        frameId: 3,
        tab: { id: 5 } as chrome.tabs.Tab,
      },
    ],
    [
      'a non-web tab',
      { id: EXTENSION_ID, url: 'file:///x.html', frameId: 0, tab: { id: 5 } as chrome.tabs.Tab },
    ],
    [
      'another extension page',
      { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/other.html` },
    ],
    ['a lookalike popup path', { id: EXTENSION_ID, url: `${POPUP_URL}.evil` }],
  ])('rejects %s', (_, sender) => {
    expect(classifySender(sender, EXTENSION_ID, POPUP_URL)).toBeNull();
  });
});

describe('handleMessage authorization', () => {
  let deps: RouterDeps;
  const content: Sender = { kind: 'content', tabId: 1, url: 'https://github.com/login' };
  const popup: Sender = { kind: 'popup' };

  beforeEach(async () => {
    const server = createFakeServer();
    await server.register('a@example.com', 'MASTER-password-123');
    const settingsStore = new MemoryStore();
    await settingsStore.set('settings', { ...DEFAULT_SETTINGS, serverUrl: SERVER });
    deps = {
      vault: new Vault({
        session: new MemoryStore(),
        local: new MemoryStore(),
        fetch: server.fetch,
        now: () => Date.now(),
        getSettings: async () => ({ ...DEFAULT_SETTINGS, serverUrl: SERVER }),
      }),
      settingsStore,
      clipboard: { scheduleClear: vi.fn(async () => {}) },
      tabs: { getUrl: vi.fn(), sendFill: vi.fn(), notifyUnlocked: vi.fn() },
    };
  });

  it.each([...POPUP_REQUEST_TYPES])(
    'content scripts cannot send popup request "%s"',
    async (type) => {
      expect(
        await handleMessage(
          { type, tabId: 1, itemId: 'x', email: 'a@example.com', password: 'x' },
          content,
          deps,
        ),
      ).toEqual({
        ok: false,
        error: 'Not allowed',
      });
    },
  );

  it.each([...CONTENT_REQUEST_TYPES])(
    'the popup cannot send content request "%s"',
    async (type) => {
      expect(await handleMessage({ type }, popup, deps)).toEqual({
        ok: false,
        error: 'Not allowed',
      });
    },
  );

  it('rejects unknown senders and malformed messages', async () => {
    expect(await handleMessage({ type: 'getState' }, null, deps)).toMatchObject({ ok: false });
    expect(await handleMessage('getState', popup, deps)).toMatchObject({ ok: false });
    expect(await handleMessage({ type: 'nope' }, popup, deps)).toMatchObject({ ok: false });
  });

  it('reports locked to content scripts before unlock', async () => {
    expect(await handleMessage({ type: 'getMatches' }, content, deps)).toEqual({
      ok: false,
      error: 'Vault is locked',
      locked: true,
    });
  });

  it('unlocks via the popup, remembers only the email, and notifies tabs', async () => {
    expect(
      await handleMessage(
        { type: 'unlock', email: 'a@example.com', password: 'MASTER-password-123' },
        popup,
        deps,
      ),
    ).toEqual({
      ok: true,
      data: null,
    });
    expect(await deps.settingsStore.get('lastEmail')).toBe('a@example.com');
    expect(deps.tabs.notifyUnlocked).toHaveBeenCalled();
    const state = await handleMessage({ type: 'getState' }, popup, deps);
    expect(state).toMatchObject({ ok: true, data: { status: 'unlocked', email: 'a@example.com' } });
  });

  it('lets the popup schedule clearing a copied password', async () => {
    expect(await handleMessage({ type: 'scheduleClipboardClear' }, popup, deps)).toEqual({
      ok: true,
      data: null,
    });
    expect(deps.clipboard.scheduleClear).toHaveBeenCalledOnce();
  });

  it('validates settings and locks when the server changes', async () => {
    await handleMessage(
      { type: 'unlock', email: 'a@example.com', password: 'MASTER-password-123' },
      popup,
      deps,
    );
    expect(
      await handleMessage(
        { type: 'saveSettings', settings: { serverUrl: 'http://evil.com', autoLockMinutes: 15 } },
        popup,
        deps,
      ),
    ).toMatchObject({
      ok: false,
    });
    expect(await deps.vault.isUnlocked()).toBe(true);
    expect(
      await handleMessage(
        {
          type: 'saveSettings',
          settings: { serverUrl: 'https://vault.example.com', autoLockMinutes: 5 },
        },
        popup,
        deps,
      ),
    ).toMatchObject({ ok: true });
    expect(await deps.vault.isUnlocked()).toBe(false);
  });
});
