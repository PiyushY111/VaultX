import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installFakeServer, type FakeServer } from '../test/fakeServer';
import { App } from './App';

// Capture every vault key the app holds so the test can check they get wiped.
const vaultKeys = vi.hoisted(() => [] as Uint8Array[]);
vi.mock('@password-manager/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@password-manager/crypto')>();
  return {
    ...actual,
    generateVaultKey: async () => {
      const key = await actual.generateVaultKey();
      vaultKeys.push(key);
      return key;
    },
    decryptVaultKey: async (...args: Parameters<typeof actual.decryptVaultKey>) => {
      const key = await actual.decryptVaultKey(...args);
      vaultKeys.push(key);
      return key;
    },
  };
});

const EMAIL = 'alice@example.com';
const PASSWORD = 'MASTER-correct-horse-battery-staple';
const ITEM = {
  site: 'github.com',
  username: 'octocat',
  password: 'ITEM-PW-hunter2-xyz',
  notes: 'work account',
};

let server: FakeServer;

beforeEach(() => {
  server = installFakeServer();
  vaultKeys.length = 0;
  localStorage.clear();
});

afterEach(() => {
  server.restore();
  vi.useRealTimers();
});

type User = ReturnType<typeof userEvent.setup>;

async function signUpAndAddItem(user: User) {
  render(<App />);
  await user.click(screen.getByRole('button', { name: 'Create an account' }));
  await user.type(screen.getByLabelText('Email'), EMAIL);
  await user.type(screen.getByLabelText('Master password'), PASSWORD);
  await user.type(screen.getByLabelText('Confirm master password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Create account' }));
  await screen.findByText(/Signed in as/, {}, { timeout: 10_000 });

  await user.click(screen.getByRole('button', { name: 'Add item' }));
  const form = screen.getByRole('form', { name: 'Add item' });
  await user.type(within(form).getByLabelText('Site'), ITEM.site);
  await user.type(within(form).getByLabelText('Username'), ITEM.username);
  await user.type(within(form).getByLabelText('Password'), ITEM.password);
  await user.type(within(form).getByLabelText('Notes'), ITEM.notes);
  await user.click(within(form).getByRole('button', { name: 'Save' }));
  await screen.findByRole('listitem', { name: ITEM.site });
}

async function unlock(user: User, password: string) {
  await user.type(screen.getByLabelText('Master password'), password);
  await user.click(screen.getByRole('button', { name: 'Unlock' }));
}

describe('signup → add item → lock → unlock', () => {
  it('clears decrypted data and keys on lock, and restores them only with the right password', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);

    // The item was encrypted before it was sent.
    const stored = [...server.items.values()];
    expect(stored).toHaveLength(1);
    const traffic = server.requests.map((r) => r.body).join('\n');
    for (const value of [PASSWORD, ...Object.values(ITEM)]) expect(traffic).not.toContain(value);

    // Search runs locally and sends nothing.
    const requestsBefore = server.requests.length;
    await user.type(screen.getByLabelText('Search vault'), 'octo');
    expect(screen.getByRole('listitem', { name: ITEM.site })).toBeInTheDocument();
    await user.clear(screen.getByLabelText('Search vault'));
    await user.type(screen.getByLabelText('Search vault'), 'no-such-site');
    expect(screen.getByText('No items match your search.')).toBeInTheDocument();
    expect(server.requests).toHaveLength(requestsBefore);
    await user.clear(screen.getByLabelText('Search vault'));

    // Lock.
    expect(vaultKeys.length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: 'Lock now' }));
    expect(screen.getByRole('heading', { name: 'Vault locked' })).toBeInTheDocument();
    expect(screen.queryByText(ITEM.site)).not.toBeInTheDocument();
    expect(screen.queryByText(ITEM.username)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(ITEM.password);
    for (const key of vaultKeys) expect(key.every((byte) => byte === 0)).toBe(true);

    // Nothing sensitive was persisted to browser storage.
    expect(Object.keys(localStorage)).toEqual([]);
    expect(Object.keys(sessionStorage)).toEqual([]);

    // Wrong password stays locked.
    await unlock(user, 'not-the-master-password');
    expect(await screen.findByRole('alert', {}, { timeout: 10_000 })).toHaveTextContent(
      'Incorrect email or master password',
    );
    expect(screen.queryByText(ITEM.site)).not.toBeInTheDocument();

    // Right password decrypts the vault again.
    await unlock(user, PASSWORD);
    const row = await screen.findByRole('listitem', { name: ITEM.site }, { timeout: 10_000 });
    expect(within(row).getByText(ITEM.username)).toBeInTheDocument();
    await user.click(within(row).getByRole('button', { name: 'Show' }));
    expect(within(row).getByText(ITEM.password)).toBeInTheDocument();
  });

  it('edits an item, re-encrypting it with a new nonce', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const before = [...server.items.values()][0]!;
    const { nonce: oldNonce, encrypted_data: oldCiphertext } = before;

    const row = screen.getByRole('listitem', { name: ITEM.site });
    await user.click(within(row).getByRole('button', { name: 'Edit' }));
    const form = screen.getByRole('form', { name: 'Edit item' });
    const passwordInput = within(form).getByLabelText('Password');
    await user.clear(passwordInput);
    await user.type(passwordInput, 'ROTATED-password-777');
    await user.click(within(form).getByRole('button', { name: 'Save' }));
    await screen.findByRole('listitem', { name: ITEM.site });

    const after = [...server.items.values()][0]!;
    expect(after.nonce).not.toBe(oldNonce);
    expect(after.encrypted_data).not.toBe(oldCiphertext);
    expect(server.requests.at(-1)!.body).not.toContain('ROTATED-password-777');
  });

  it('fills the item password from the generator', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    await user.click(screen.getByRole('button', { name: 'Add item' }));
    const form = screen.getByRole('form', { name: 'Add item' });
    await user.click(within(form).getByRole('button', { name: 'Generate…' }));
    const generated = within(form).getByLabelText('Generated password').textContent!;
    expect(generated).toHaveLength(20);
    await user.click(within(form).getByRole('button', { name: 'Use this password' }));
    expect(within(form).getByLabelText('Password')).toHaveValue(generated);
  });
});

describe('auto-lock', () => {
  it('locks after the configured inactivity timeout and wipes keys', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await signUpAndAddItem(user);

    await user.selectOptions(screen.getByLabelText('Auto-lock after'), '1');
    expect(localStorage.getItem('password-manager.autoLockMinutes')).toBe('1');

    act(() => {
      vi.advanceTimersByTime(30_000);
    });
    expect(screen.getByRole('listitem', { name: ITEM.site })).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(31_000);
    });
    expect(screen.getByRole('heading', { name: 'Vault locked' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Locked after 1 minute of inactivity.');
    expect(screen.queryByText(ITEM.site)).not.toBeInTheDocument();
    for (const key of vaultKeys) expect(key.every((byte) => byte === 0)).toBe(true);
  });
});

describe('session expiry', () => {
  it('locks the vault when the server rejects the session', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    server.expireAllSessions();

    const row = screen.getByRole('listitem', { name: ITEM.site });
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await user.click(within(row).getByRole('button', { name: 'Delete' }));
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Vault locked' })).toBeInTheDocument(),
    );
    expect(screen.getByRole('status')).toHaveTextContent('session expired');
  });
});
