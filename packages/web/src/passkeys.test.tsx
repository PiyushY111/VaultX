import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  FAKE_TOTP_CODE,
  fakePasskeyResponse,
  installFakeServer,
  type FakeServer,
} from '../test/fakeServer';
import { App } from './App';

// The browser's WebAuthn API, replaced by a fake authenticator that holds one
// credential and signs whatever challenge it's given.
const webauthn = vi.hoisted(() => ({
  credentialId: 'cred-1',
  /** Set to make the next prompt fail as if the user closed it. */
  cancelNext: false,
  startRegistration: vi.fn(),
  startAuthentication: vi.fn(),
}));
vi.mock('@simplewebauthn/browser', () => {
  class WebAuthnError extends Error {
    code = 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY';
  }
  const cancelled = () =>
    Object.assign(new Error('The operation was aborted.'), { name: 'NotAllowedError' });
  webauthn.startRegistration.mockImplementation(async ({ optionsJSON }) => {
    if (webauthn.cancelNext) {
      webauthn.cancelNext = false;
      throw cancelled();
    }
    return fakePasskeyResponse(webauthn.credentialId, optionsJSON.challenge);
  });
  webauthn.startAuthentication.mockImplementation(async ({ optionsJSON }) => {
    if (webauthn.cancelNext) {
      webauthn.cancelNext = false;
      throw cancelled();
    }
    return fakePasskeyResponse(webauthn.credentialId, optionsJSON.challenge);
  });
  return {
    WebAuthnError,
    browserSupportsWebAuthn: () => true,
    startRegistration: webauthn.startRegistration,
    startAuthentication: webauthn.startAuthentication,
  };
});

const EMAIL = 'pat@example.com';
const PASSWORD = 'MASTER-passkeys-are-phishing-resistant';

let server: FakeServer;

beforeEach(() => {
  server = installFakeServer();
  webauthn.cancelNext = false;
  webauthn.startRegistration.mockClear();
  webauthn.startAuthentication.mockClear();
  localStorage.clear();
});

afterEach(() => {
  server.restore();
});

type User = ReturnType<typeof userEvent.setup>;

async function signUp(user: User) {
  render(<App />);
  await user.click(screen.getByRole('button', { name: 'Create an account' }));
  await user.type(screen.getByLabelText('Email'), EMAIL);
  await user.type(screen.getByLabelText('Master password'), PASSWORD);
  await user.type(screen.getByLabelText('Confirm master password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Create account' }));
  await screen.findByText(/Signed in as/, {}, { timeout: 10_000 });
  await user.click(screen.getByRole('button', { name: 'Security' }));
}

const passkeysSection = () => screen.getByRole('region', { name: 'Passkeys' });

async function addFirstPasskey(user: User): Promise<string[]> {
  await user.click(within(passkeysSection()).getByRole('button', { name: 'Add a passkey' }));
  const form = within(passkeysSection()).getByRole('form', { name: 'Add a passkey' });
  await user.clear(within(form).getByLabelText('Passkey name'));
  await user.type(within(form).getByLabelText('Passkey name'), 'Laptop');
  await user.type(within(form).getByLabelText('Master password'), PASSWORD);
  await user.click(within(form).getByRole('button', { name: 'Create passkey' }));
  const codes = await within(passkeysSection()).findByRole(
    'region',
    { name: 'Recovery codes' },
    { timeout: 10_000 },
  );
  const list = within(codes)
    .getAllByRole('listitem')
    .map((li) => li.textContent!);
  await user.click(within(codes).getByRole('button', { name: 'I’ve saved them' }));
  return list;
}

async function lockAndEnterPassword(user: User) {
  await user.click(screen.getByRole('button', { name: 'Lock now' }));
  await user.type(screen.getByLabelText('Master password'), PASSWORD);
  await user.click(screen.getByRole('button', { name: 'Unlock' }));
  return screen.findByRole('form', { name: 'Two-factor code' }, { timeout: 10_000 });
}

describe('passkeys', () => {
  it('adds a passkey with the master password, and shows recovery codes for the first factor', async () => {
    const user = userEvent.setup();
    await signUp(user);
    const codes = await addFirstPasskey(user);
    expect(codes).toHaveLength(10);
    expect(within(passkeysSection()).getByRole('listitem', { name: 'Laptop' })).toBeInTheDocument();
    const stored = server.users.get(EMAIL)!;
    expect(stored.passkeys.map((p) => p.name)).toEqual(['Laptop']);
    // The registration request carried only the authenticator's response, never the password.
    const finish = server.requests.find(
      (r) => r.url === '/api/account/passkeys' && r.method === 'POST',
    )!;
    expect(finish.body).not.toContain(PASSWORD);
    expect(Object.keys(JSON.parse(finish.body)).sort()).toEqual(['name', 'response']);
  });

  it('unlocks with the passkey after the password; no TOTP field when the account has none', async () => {
    const user = userEvent.setup();
    await signUp(user);
    await addFirstPasskey(user);
    const form = await lockAndEnterPassword(user);
    expect(within(form).queryByLabelText('Authentication code')).not.toBeInTheDocument();
    expect(within(form).queryByRole('button', { name: 'Use my authenticator app' })).toBeNull();
    await user.click(within(form).getByRole('button', { name: 'Use passkey' }));
    expect(await screen.findByText(/Signed in as/, {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(webauthn.startAuthentication).toHaveBeenCalledTimes(1);
  });

  it('shows a clear error when the prompt is closed, then works on retry with a fresh challenge', async () => {
    const user = userEvent.setup();
    await signUp(user);
    await addFirstPasskey(user);
    const form = await lockAndEnterPassword(user);
    webauthn.cancelNext = true;
    await user.click(within(form).getByRole('button', { name: 'Use passkey' }));
    expect(await within(form).findByRole('alert')).toHaveTextContent(/closed or timed out/);
    await user.click(within(form).getByRole('button', { name: 'Use passkey' }));
    expect(await screen.findByText(/Signed in as/, {}, { timeout: 10_000 })).toBeInTheDocument();
  });

  it('falls back to a recovery code', async () => {
    const user = userEvent.setup();
    await signUp(user);
    const codes = await addFirstPasskey(user);
    const form = await lockAndEnterPassword(user);
    await user.click(within(form).getByRole('button', { name: 'Use a recovery code' }));
    await user.type(within(form).getByLabelText('Recovery code'), codes[0]!);
    await user.click(within(form).getByRole('button', { name: 'Verify' }));
    expect(await screen.findByText(/Signed in as/, {}, { timeout: 10_000 })).toBeInTheDocument();
  });

  it('"Require passkey" hides the authenticator-app option at login', async () => {
    const user = userEvent.setup();
    await signUp(user);
    await addFirstPasskey(user);
    // Turn on TOTP too (it needs the passkey, as an existing factor).
    const twoFactor = screen.getByRole('region', { name: 'Two-factor login' });
    await user.click(within(twoFactor).getByRole('button', { name: 'Set up two-factor login' }));
    const setup = await within(twoFactor).findByRole('form', { name: 'Set up two-factor login' });
    await user.type(within(setup).getByLabelText('Code from the app'), FAKE_TOTP_CODE);
    await user.type(within(setup).getByLabelText('Master password'), PASSWORD);
    await user.click(within(setup).getByRole('button', { name: 'Turn on two-factor login' }));
    const codes = await within(twoFactor).findByRole(
      'region',
      { name: 'Recovery codes' },
      { timeout: 10_000 },
    );
    await user.click(within(codes).getByRole('button', { name: 'I’ve saved them' }));
    expect(server.users.get(EMAIL)!.totpEnabled).toBe(true);

    await user.click(
      within(passkeysSection()).getByRole('button', {
        name: 'Require passkey (turn off authenticator codes for login)',
      }),
    );
    const form = within(passkeysSection()).getByRole('form', { name: 'Require passkey' });
    await user.type(within(form).getByLabelText('Master password'), PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Require passkey' }));
    expect(
      await within(passkeysSection()).findByRole('status', {}, { timeout: 10_000 }),
    ).toHaveTextContent('A passkey is required');
    expect(server.users.get(EMAIL)!.passkeyRequired).toBe(true);

    const login = await lockAndEnterPassword(user);
    expect(within(login).queryByRole('button', { name: 'Use my authenticator app' })).toBeNull();
    expect(within(login).getByRole('button', { name: 'Use a recovery code' })).toBeInTheDocument();
  });

  it('removes a passkey only after the password and a passkey confirmation', async () => {
    const user = userEvent.setup();
    await signUp(user);
    await addFirstPasskey(user);
    await user.click(within(passkeysSection()).getByRole('button', { name: 'Remove' }));
    const form = within(passkeysSection()).getByRole('form', { name: 'Remove passkey' });
    expect(form).toHaveTextContent(/only second factor/);
    await user.type(within(form).getByLabelText('Master password'), PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Remove passkey' }));
    await within(passkeysSection()).findByRole(
      'button',
      { name: 'Add a passkey' },
      { timeout: 10_000 },
    );
    const stored = server.users.get(EMAIL)!;
    expect(stored.passkeys).toEqual([]);
    expect(stored.recoveryCodes).toEqual([]);
    const remove = server.requests.find(
      (r) => r.method === 'DELETE' && r.url.startsWith('/api/account/passkeys/'),
    )!;
    expect(JSON.parse(remove.body)).toHaveProperty('webauthn');
  });

  it('renames a passkey', async () => {
    const user = userEvent.setup();
    await signUp(user);
    await addFirstPasskey(user);
    await user.click(within(passkeysSection()).getByRole('button', { name: 'Rename' }));
    const form = within(passkeysSection()).getByRole('form', { name: 'Rename passkey' });
    expect(within(form).queryByLabelText('Master password')).toBeNull();
    await user.clear(within(form).getByLabelText('Passkey name'));
    await user.type(within(form).getByLabelText('Passkey name'), 'Work laptop');
    await user.click(within(form).getByRole('button', { name: 'Save name' }));
    expect(
      await within(passkeysSection()).findByRole('listitem', { name: 'Work laptop' }),
    ).toBeInTheDocument();
  });

  it('asks for the passkey when deleting the account', async () => {
    const user = userEvent.setup();
    await signUp(user);
    await addFirstPasskey(user);
    const form = screen.getByRole('form', { name: 'Delete account' });
    expect(within(form).getByText(/confirm with your passkey/)).toBeInTheDocument();
    await user.type(within(form).getByLabelText('Type your email to confirm'), EMAIL);
    await user.type(within(form).getByLabelText('Master password'), PASSWORD);
    await user.click(within(form).getByRole('button', { name: 'Delete account permanently' }));
    await screen.findByRole('button', { name: 'Log in' }, { timeout: 10_000 });
    expect(server.users.has(EMAIL)).toBe(false);
  });
});
