import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import sodium from 'libsodium-wrappers-sumo';
import { FAKE_TOTP_CODE, installFakeServer, type FakeServer } from '../test/fakeServer';
import { App } from './App';
import { toBase64 } from './lib/base64';
import { CLIPBOARD_CLEAR_MS } from './lib/clipboard';
import { serializeItem } from './vault/items';
import { revisionStorageKey } from './vault/revisionLedger';

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

    // Nothing sensitive was persisted to browser storage: only the revision
    // ledger, which holds item ids and revision numbers.
    expect(Object.keys(localStorage)).toEqual([revisionStorageKey(EMAIL)]);
    const ledger = JSON.parse(localStorage.getItem(revisionStorageKey(EMAIL))!);
    expect(ledger).toEqual({ [stored[0]!.id]: 1, '#manifest': 2 });
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

describe('master password strength', () => {
  it('refuses a weak master password at signup, before any network or crypto work', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Create an account' }));
    await user.type(screen.getByLabelText('Email'), EMAIL);
    await user.type(screen.getByLabelText('Master password'), 'password1234');
    await user.type(screen.getByLabelText('Confirm master password'), 'password1234');
    const meter = await screen.findByRole(
      'meter',
      { name: 'Password strength' },
      { timeout: 5_000 },
    );
    await waitFor(() => expect(Number(meter.getAttribute('aria-valuenow'))).toBeLessThan(3));
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/rated at least “Strong”/);
    expect(server.requests).toHaveLength(0);
  });
});

describe('clipboard', () => {
  // user-event's clipboard stub throws when reading an empty clipboard.
  const readClipboard = () => navigator.clipboard.readText().catch(() => '');

  it('clears a copied password after 30 seconds, and immediately on lock', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await signUpAndAddItem(user);
    const row = screen.getByRole('listitem', { name: ITEM.site });

    await user.click(within(row).getByRole('button', { name: 'Copy' }));
    expect(await readClipboard()).toBe(ITEM.password);
    await act(() => vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS));
    expect(await readClipboard()).toBe('');

    await user.click(within(row).getByRole('button', { name: 'Copy' }));
    expect(await readClipboard()).toBe(ITEM.password);
    await user.click(screen.getByRole('button', { name: 'Lock now' }));
    await waitFor(async () => expect(await readClipboard()).toBe(''));
  });
});

describe('sessions', () => {
  it('ends the server session on lock, and lists and signs out sessions from Security', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    await user.click(screen.getByRole('button', { name: 'Lock now' }));
    await waitFor(() => expect(server.sessions.size).toBe(0));
    await unlock(user, PASSWORD);
    await screen.findByRole('listitem', { name: ITEM.site }, { timeout: 10_000 });

    await user.click(screen.getByRole('button', { name: 'Security' }));
    const sessions = await screen.findByRole('region', { name: 'Sessions' });
    const current = await within(sessions).findByRole('listitem', {
      name: 'Web vault · Chrome on macOS',
    });
    expect(within(current).getByText('This session')).toBeInTheDocument();

    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await user.click(within(sessions).getByRole('button', { name: 'Sign out everywhere' }));
    expect(await screen.findByRole('heading', { name: 'Log in' })).toBeInTheDocument();
    expect(server.sessions.size).toBe(0);
  });
});

describe('change master password', () => {
  const NEW_PASSWORD = 'NEW-master-password-orbit-lantern-58';

  it('re-encrypts the vault so only the new password opens it', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const before = { ...[...server.items.values()][0]! };

    await user.click(screen.getByRole('button', { name: 'Security' }));
    const form = screen.getByRole('form', { name: 'Change master password' });
    await user.type(within(form).getByLabelText('Current master password'), PASSWORD);
    await user.type(within(form).getByLabelText('New master password'), NEW_PASSWORD);
    await user.type(within(form).getByLabelText('Confirm new master password'), NEW_PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Change master password' }));
    expect(await within(form).findByRole('status', {}, { timeout: 20_000 })).toHaveTextContent(
      'Master password changed',
    );

    const after = [...server.items.values()][0]!;
    expect(after.revision).toBe(before.revision + 1);
    expect(after.encrypted_data).not.toBe(before.encrypted_data);
    const traffic = server.requests.map((r) => r.body).join('\n');
    for (const value of [PASSWORD, NEW_PASSWORD, ITEM.password])
      expect(traffic).not.toContain(value);

    await user.click(screen.getByRole('button', { name: 'Lock now' }));
    await unlock(user, PASSWORD);
    expect(await screen.findByRole('alert', {}, { timeout: 10_000 })).toHaveTextContent(
      'Incorrect email or master password',
    );
    await unlock(user, NEW_PASSWORD);
    expect(
      await screen.findByRole('listitem', { name: ITEM.site }, { timeout: 10_000 }),
    ).toBeInTheDocument();
  });

  it('says so when the current password is wrong', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    await user.click(screen.getByRole('button', { name: 'Security' }));
    const form = screen.getByRole('form', { name: 'Change master password' });
    await user.type(within(form).getByLabelText('Current master password'), 'not-my-password-1');
    await user.type(within(form).getByLabelText('New master password'), NEW_PASSWORD);
    await user.type(within(form).getByLabelText('Confirm new master password'), NEW_PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Change master password' }));
    expect(await within(form).findByRole('alert', {}, { timeout: 10_000 })).toHaveTextContent(
      'Current master password is incorrect',
    );
    expect(server.requests.some((r) => r.url === '/api/account/password')).toBe(false);
  });
});

describe('item revisions', () => {
  it('hides an item the server has rolled back to an older revision', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const original = { ...[...server.items.values()][0]! };

    const row = screen.getByRole('listitem', { name: ITEM.site });
    await user.click(within(row).getByRole('button', { name: 'Edit' }));
    const form = screen.getByRole('form', { name: 'Edit item' });
    await user.clear(within(form).getByLabelText('Password'));
    await user.type(within(form).getByLabelText('Password'), 'ROTATED-password-777');
    await user.click(within(form).getByRole('button', { name: 'Save' }));
    await screen.findByRole('listitem', { name: ITEM.site });

    // A malicious server restores the old (genuine) ciphertext of revision 1.
    server.items.set(original.id, original);
    await user.click(screen.getByRole('button', { name: 'Lock now' }));
    await unlock(user, PASSWORD);
    expect(await screen.findByRole('alert', {}, { timeout: 10_000 })).toHaveTextContent(
      /older than a version this browser has already seen/,
    );
    expect(screen.queryByRole('listitem', { name: ITEM.site })).not.toBeInTheDocument();
  });

  it('upgrades an item saved before revisions existed', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const vaultKey = vaultKeys[0]!.slice();
    await user.click(screen.getByRole('button', { name: 'Lock now' }));

    await sodium.ready;
    const nonce = sodium.randombytes_buf(24);
    const legacyItem = { site: 'legacy.example.com', username: 'old', password: 'pw', notes: '' };
    const id = crypto.randomUUID();
    server.items.set(id, {
      id,
      owner: 'alice@example.com',
      revision: 0,
      encrypted_data: toBase64(
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          serializeItem(legacyItem),
          'password-manager:v1:item',
          null,
          nonce,
          vaultKey,
        ),
      ),
      nonce: toBase64(nonce),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    // As on an account from before manifests existed: none on the server, none seen here.
    server.users.get('alice@example.com')!.manifest = null;
    localStorage.clear();

    await unlock(user, PASSWORD);
    expect(
      await screen.findByRole('listitem', { name: legacyItem.site }, { timeout: 10_000 }),
    ).toBeInTheDocument();
    await waitFor(() => expect(server.items.get(id)!.revision).toBe(1));
    // It's in the vault's new manifest, so the next load is clean.
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('reloads instead of overwriting an item that changed elsewhere', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const row = screen.getByRole('listitem', { name: ITEM.site });
    await user.click(within(row).getByRole('button', { name: 'Edit' }));
    // Another device saves revision 2 in the meantime.
    [...server.items.values()][0]!.revision = 2;
    const form = screen.getByRole('form', { name: 'Edit item' });
    await user.type(within(form).getByLabelText('Notes'), ' (edited)');
    await user.click(within(form).getByRole('button', { name: 'Save' }));
    expect(await within(form).findByRole('alert')).toHaveTextContent(/changed elsewhere/);
  });
});

describe('emergency kit', () => {
  it('is offered right after signup, without the master password in it', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const kit = screen.getByRole('region', { name: 'Emergency kit' });
    expect(within(kit).getByText(/VAULTX EMERGENCY KIT/)).toHaveTextContent(EMAIL);
    expect(kit.textContent).not.toContain(PASSWORD);

    const createObjectURL = vi.fn(() => 'blob:kit');
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    await user.click(within(kit).getByRole('button', { name: 'Download' }));
    const blob = (createObjectURL.mock.calls[0] as unknown as [Blob])[0];
    expect(await blob.text()).toContain(EMAIL);

    await user.click(within(kit).getByRole('button', { name: 'I’ve saved it' }));
    expect(screen.queryByRole('region', { name: 'Emergency kit' })).not.toBeInTheDocument();
  });
});

describe('two-factor login', () => {
  async function turnOnTwoFactor(user: User) {
    await user.click(screen.getByRole('button', { name: 'Security' }));
    const section = screen.getByRole('region', { name: 'Two-factor login' });
    await user.click(
      await within(section).findByRole('button', { name: 'Set up two-factor login' }),
    );
    const form = await within(section).findByRole('form', { name: 'Set up two-factor login' });
    expect(within(form).getByRole('img', { name: /QR code/ })).toBeInTheDocument();
    await user.type(within(form).getByLabelText('Code from the app'), FAKE_TOTP_CODE);
    await user.type(within(form).getByLabelText('Master password'), PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Turn on two-factor login' }));
    const codes = await within(section).findByRole(
      'region',
      { name: 'Recovery codes' },
      { timeout: 10_000 },
    );
    const list = within(codes)
      .getAllByRole('listitem')
      .map((li) => li.textContent!);
    expect(list).toHaveLength(10);
    await user.click(within(codes).getByRole('button', { name: 'I’ve saved them' }));
    expect(await within(section).findByRole('status')).toHaveTextContent(
      'Two-factor login is on. 10 recovery codes left.',
    );
    return list;
  }

  it('is set up from Security, then asked for after the password', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    const recoveryCodes = await turnOnTwoFactor(user);

    await user.click(screen.getByRole('button', { name: 'Lock now' }));
    await unlock(user, PASSWORD);
    const form = await screen.findByRole('form', { name: 'Two-factor code' }, { timeout: 10_000 });
    await user.type(within(form).getByLabelText('Authentication code'), '000000');
    await user.click(within(form).getByRole('button', { name: 'Verify' }));
    expect(await within(form).findByRole('alert')).toHaveTextContent(/incorrect/);

    await user.click(within(form).getByRole('button', { name: 'Use a recovery code' }));
    await user.type(within(form).getByLabelText('Recovery code'), recoveryCodes[0]!);
    await user.click(within(form).getByRole('button', { name: 'Verify' }));
    expect(
      await screen.findByRole('listitem', { name: ITEM.site }, { timeout: 10_000 }),
    ).toBeInTheDocument();
  });
});

describe('delete account', () => {
  it('deletes everything after the email and master password are confirmed', async () => {
    const user = userEvent.setup();
    await signUpAndAddItem(user);
    await user.click(screen.getByRole('button', { name: 'Security' }));
    const form = screen.getByRole('form', { name: 'Delete account' });

    await user.type(within(form).getByLabelText('Type your email to confirm'), 'wrong@example.com');
    await user.type(within(form).getByLabelText('Master password'), PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Delete account permanently' }));
    expect(within(form).getByRole('alert')).toHaveTextContent('Type your email exactly');
    expect(server.users.size).toBe(1);

    await user.clear(within(form).getByLabelText('Type your email to confirm'));
    await user.type(within(form).getByLabelText('Type your email to confirm'), EMAIL);
    await user.clear(within(form).getByLabelText('Master password'));
    await user.type(within(form).getByLabelText('Master password'), PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Delete account permanently' }));
    expect(
      await screen.findByRole('heading', { name: 'Log in' }, { timeout: 10_000 }),
    ).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('were deleted');
    expect(server.users.size).toBe(0);
    expect(server.items.size).toBe(0);
    expect(Object.keys(localStorage)).toEqual([]);
  });
});
