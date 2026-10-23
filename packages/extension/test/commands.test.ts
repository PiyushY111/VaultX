import { beforeEach, describe, expect, it, vi } from 'vitest';
import { handleFillCommand, handleMenuClick, type CommandDeps } from '../src/background/commands';
import { DEFAULT_SETTINGS } from '../src/background/settings';
import { Vault } from '../src/background/vault';
import type { BackgroundToContent } from '../src/shared/messages';
import { MemoryStore, SERVER, createFakeServer } from './helpers';

const EMAIL = 'a@example.com';
const PASSWORD = 'MASTER-password-123';
const TAB = { id: 7, url: 'https://shop.example.com/login' };
const login = (username: string, extra: object = {}) => ({
  site: 'shop.example.com',
  username,
  password: `${username}-PW`,
  notes: '',
  ...extra,
});

let server: ReturnType<typeof createFakeServer>;
let vaultKey: Uint8Array;
let sent: [number, BackgroundToContent][];
let deps: CommandDeps & { openPopup: ReturnType<typeof vi.fn> };

beforeEach(async () => {
  server = createFakeServer();
  vaultKey = await server.register(EMAIL, PASSWORD);
  sent = [];
  deps = {
    vault: new Vault({
      session: new MemoryStore(),
      local: new MemoryStore(),
      fetch: server.fetch,
      now: () => 1_000_000,
      getSettings: async () => ({ ...DEFAULT_SETTINGS, serverUrl: SERVER }),
    }),
    send: vi.fn(async (tabId: number, message: BackgroundToContent) => {
      sent.push([tabId, message]);
    }),
    generatePassword: () => 'GENERATED-Pw-42!',
    openPopup: vi.fn(async () => {}),
  };
});

const unlock = () => deps.vault.unlock(EMAIL, PASSWORD);
const messages = () => sent.map(([, message]) => message);

describe('the fill shortcut', () => {
  it('fills the only login for the page at once: a browser shortcut is a real keypress', async () => {
    await server.seedItem(vaultKey, login('octo'));
    await unlock();
    await handleFillCommand(TAB, deps);
    expect(sent).toEqual([
      [
        7,
        {
          type: 'fillCredential',
          username: 'octo',
          password: 'octo-PW',
          host: 'shop.example.com',
        },
      ],
    ]);
  });

  it('asks which login when there are several, sending none of them', async () => {
    await server.seedItem(vaultKey, login('one'));
    await server.seedItem(vaultKey, login('two'));
    await unlock();
    await handleFillCommand(TAB, deps);
    expect(messages()).toEqual([{ type: 'showChooser', kind: 'login' }]);
  });

  it('says so when there’s no login for the page', async () => {
    await unlock();
    await handleFillCommand(TAB, deps);
    expect(messages()).toEqual([
      expect.objectContaining({ type: 'showNotice', message: 'No saved login for this site' }),
    ]);
  });

  it('opens the popup to unlock, or says the vault is locked where it can’t', async () => {
    await server.seedItem(vaultKey, login('octo'));
    await handleFillCommand(TAB, deps);
    expect(deps.openPopup).toHaveBeenCalled();
    expect(sent).toEqual([]);

    // Where chrome.action.openPopup isn't available.
    const withoutPopup: CommandDeps = {
      vault: deps.vault,
      send: deps.send,
      generatePassword: deps.generatePassword,
    };
    await handleFillCommand(TAB, withoutPopup);
    expect(messages()).toEqual([expect.objectContaining({ message: 'VaultX is locked' })]);
  });

  it('does nothing on insecure or non-web pages, or without a tab', async () => {
    await server.seedItem(vaultKey, login('octo'));
    await unlock();
    for (const tab of [
      { id: 7, url: 'http://shop.example.com/login' },
      { id: 7, url: 'chrome://settings' },
      { id: 7 },
      { url: TAB.url },
    ]) {
      await handleFillCommand(tab, deps);
    }
    expect(sent).toEqual([]);
  });
});

describe('the right-click menu', () => {
  it('fills a login, or a two-factor code, for the page', async () => {
    await server.seedItem(vaultKey, login('octo', { totp: 'JBSWY3DPEHPK3PXP' }));
    await unlock();
    await handleMenuClick('fill-login', 0, TAB, deps);
    await handleMenuClick('fill-totp', 0, TAB, deps);
    expect(messages()).toEqual([
      expect.objectContaining({ type: 'fillCredential', username: 'octo' }),
      { type: 'fillTotpCode', code: expect.stringMatching(/^\d{6}$/), host: 'shop.example.com' },
    ]);
  });

  it('fills the only saved card, or asks which one', async () => {
    const card = {
      type: 'card' as const,
      site: 'Visa',
      username: '',
      password: '',
      notes: '',
      fields: { number: '4111111111114242', expiry: '03/27' },
    };
    await server.seedItem(vaultKey, card);
    await unlock();
    await handleMenuClick('fill-card', 0, TAB, deps);
    expect(messages()).toEqual([
      { type: 'fillForm', kind: 'card', host: 'shop.example.com', values: card.fields },
    ]);

    await server.seedItem(vaultKey, { ...card, site: 'Amex' });
    const fresh = new Vault({
      session: new MemoryStore(),
      local: new MemoryStore(),
      fetch: server.fetch,
      now: () => 1_000_000,
      getSettings: async () => ({ ...DEFAULT_SETTINGS, serverUrl: SERVER }),
    });
    await fresh.unlock(EMAIL, PASSWORD);
    await handleMenuClick('fill-card', 0, TAB, { ...deps, vault: fresh });
    expect(messages().at(-1)).toEqual({ type: 'showChooser', kind: 'card' });
  });

  it('generates a password, even while locked, and keeps it for the popup', async () => {
    await handleMenuClick('generate', 0, TAB, deps);
    expect(messages()).toEqual([
      { type: 'fillGenerated', password: 'GENERATED-Pw-42!', host: 'shop.example.com' },
    ]);
    expect(await deps.vault.generatedFor(7)).toMatchObject({
      host: 'shop.example.com',
      password: 'GENERATED-Pw-42!',
    });
  });

  it('won’t fill inside an embedded frame, where our script doesn’t run', async () => {
    await server.seedItem(vaultKey, login('octo'));
    await unlock();
    for (const item of ['fill-login', 'fill-totp', 'fill-card', 'generate'])
      await handleMenuClick(item, 3, TAB, deps);
    expect(messages()).toHaveLength(4);
    expect(messages().every((m) => m.type === 'showNotice')).toBe(true);
    expect(await deps.vault.generatedFor(7)).toBeNull();
  });

  it('ignores entries it doesn’t know', async () => {
    await handleMenuClick('something-else', 0, TAB, deps);
    expect(sent).toEqual([]);
  });
});
