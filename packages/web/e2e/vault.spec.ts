import { createHmac } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';

const ITEM = {
  site: 'github.com',
  username: 'e2e-octocat',
  password: 'E2E-ITEM-PASSWORD-hunter2',
  notes: 'E2E private notes',
};

function uniqueAccount() {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return { email: `e2e-${id}@example.com`, password: `E2E-MASTER-${id}-correct-horse` };
}

/** Records every API request and any console error (including CSP violations). */
function watch(page: Page) {
  const requests: string[] = [];
  const errors: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/')) {
      requests.push(
        `${request.method()} ${request.url()}\n${JSON.stringify(request.headers())}\n${request.postData() ?? ''}`,
      );
    }
  });
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('pageerror', (error) => errors.push(error.message));
  return { requests, errors };
}

async function signUp(page: Page, account: { email: string; password: string }, url = '/') {
  await page.goto(url);
  await page.getByRole('button', { name: 'Create an account' }).click();
  await page.getByLabel('Email').fill(account.email);
  await page.getByLabel('Master password', { exact: true }).fill(account.password);
  await page.getByLabel('Confirm master password').fill(account.password);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText(`Signed in as ${account.email}`)).toBeVisible();
}

async function addItem(page: Page) {
  await page.getByRole('button', { name: 'Add item' }).click();
  const form = page.getByRole('form', { name: 'Add item' });
  await form.getByLabel('Site').fill(ITEM.site);
  await form.getByLabel('Username').fill(ITEM.username);
  await form.getByLabel('Password', { exact: true }).fill(ITEM.password);
  await form.getByLabel('Notes').fill(ITEM.notes);
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();
}

test('signup → add item → lock → unlock sends only ciphertext', async ({ page }) => {
  const account = uniqueAccount();
  const { requests, errors } = watch(page);

  await signUp(page, account);
  await addItem(page);

  await page.getByRole('button', { name: 'Lock now' }).click();
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await expect(page.getByText(ITEM.site)).toHaveCount(0);

  await page.getByLabel('Master password').fill('definitely-not-the-password');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('alert')).toHaveText(
    'Incorrect email or master password. 4 attempts left before this account is temporarily locked.',
  );

  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Unlock' }).click();
  const row = page.getByRole('listitem', { name: ITEM.site });
  await expect(row).toBeVisible();
  await expect(row.getByText(ITEM.username)).toBeVisible();
  await row.getByRole('button', { name: 'Show' }).click();
  await expect(row.getByText(ITEM.password)).toBeVisible();

  // Every request the browser made: no master password, no item plaintext.
  expect(requests.length).toBeGreaterThan(5);
  for (const request of requests) {
    for (const secret of [
      account.password,
      'definitely-not-the-password',
      ...Object.values(ITEM),
    ]) {
      expect(request, `leaked "${secret}"`).not.toContain(secret);
    }
  }
  // One expected 401 from the wrong-password attempt; nothing else, and no CSP violations.
  expect(errors.filter((e) => !e.includes('401'))).toEqual([]);
});

test('auto-lock clears the vault after inactivity', async ({ page }) => {
  await page.clock.install();
  const account = uniqueAccount();
  await signUp(page, account);
  await addItem(page);

  await page.getByLabel('Auto-lock after').selectOption('1');
  await page.clock.fastForward('00:30');
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();

  await page.clock.fastForward('00:35');
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await expect(page.getByRole('status')).toHaveText('Locked after 1 minute of inactivity.');
  await expect(page.getByText(ITEM.site)).toHaveCount(0);

  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();
});

test('derives keys in a Web Worker, allowed by the production CSP', async ({ page }) => {
  const workers: string[] = [];
  page.on('worker', (worker) => workers.push(worker.url()));
  const { errors } = watch(page);
  await signUp(page, uniqueAccount());
  expect(workers.some((url) => url.includes('kdf.worker'))).toBe(true);
  expect(errors).toEqual([]);
});

test('changes the master password, then only the new one unlocks', async ({ page }) => {
  const account = uniqueAccount();
  const newPassword = `${account.password}-ROTATED`;
  const { requests } = watch(page);
  await signUp(page, account);
  await addItem(page);

  await page.getByRole('button', { name: 'Security' }).click();
  const sessions = page.getByRole('region', { name: 'Sessions' });
  await expect(sessions.getByRole('listitem', { name: /^Web vault/ })).toContainText(
    'This session',
  );

  const form = page.getByRole('form', { name: 'Change master password' });
  await form.getByLabel('Current master password').fill(account.password);
  await form.getByLabel('New master password', { exact: true }).fill(newPassword);
  await form.getByLabel('Confirm new master password').fill(newPassword);
  await form.getByRole('button', { name: 'Change master password' }).click();
  await expect(form.getByRole('status')).toContainText('Master password changed');

  await page.getByRole('button', { name: 'Lock now' }).click();
  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('alert')).toContainText('Incorrect email or master password');
  await page.getByLabel('Master password').fill(newPassword);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();

  for (const request of requests) {
    for (const secret of [account.password, newPassword, ...Object.values(ITEM)]) {
      expect(request, `leaked "${secret}"`).not.toContain(secret);
    }
  }
});

test('clears a copied password from the clipboard after 30 seconds', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.clock.install();
  await signUp(page, uniqueAccount());
  await addItem(page);
  const readClipboard = () => page.evaluate(() => navigator.clipboard.readText());

  await page
    .getByRole('listitem', { name: ITEM.site })
    .getByRole('button', { name: 'Copy' })
    .click();
  await expect.poll(readClipboard).toBe(ITEM.password);
  await page.clock.fastForward('00:31');
  await expect.poll(readClipboard).toBe('');
});

/** RFC 6238 TOTP for a base32 secret, as an authenticator app computes it. */
function totp(base32: string, now = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32.replace(/\s/g, '')) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  }
  const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30_000)));
  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest[19]! & 0x0f;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

test('two-factor login and account deletion, end to end', async ({ page }) => {
  const account = uniqueAccount();
  await signUp(page, account);
  await expect(page.getByRole('region', { name: 'Emergency kit' })).toContainText(account.email);
  await page.getByRole('button', { name: 'I’ve saved it' }).click();
  await addItem(page);

  // Turn on two-factor with a code computed from the key shown on screen.
  await page.getByRole('button', { name: 'Security' }).click();
  const section = page.getByRole('region', { name: 'Two-factor login' });
  await section.getByRole('button', { name: 'Set up two-factor login' }).click();
  const setup = section.getByRole('form', { name: 'Set up two-factor login' });
  await expect(setup.getByRole('img', { name: /QR code/ })).toBeVisible();
  const secret = (await setup.locator('.totp-secret').textContent())!;
  await setup.getByLabel('Code from the app').fill(totp(secret));
  await setup.getByLabel('Master password').fill(account.password);
  await setup.getByRole('button', { name: 'Turn on two-factor login' }).click();
  const codes = section.getByRole('region', { name: 'Recovery codes' });
  await expect(codes.getByRole('listitem')).toHaveCount(10);
  const recoveryCode = (await codes.getByRole('listitem').first().textContent())!;
  await codes.getByRole('button', { name: 'I’ve saved them' }).click();
  await expect(section.getByRole('status')).toContainText('Two-factor login is on');

  // Unlocking now needs a code (the next time step: each code works once).
  await page.getByRole('button', { name: 'Lock now' }).click();
  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Unlock' }).click();
  const second = page.getByRole('form', { name: 'Two-factor code' });
  await second.getByLabel('Authentication code').fill(totp(secret, Date.now() + 30_000));
  await second.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();
  await expect(page.getByTestId('last-changed')).toContainText('the web vault');

  // Delete the account (password + a recovery code, since the next TOTP code
  // isn't valid yet), and it's gone.
  await page.getByRole('button', { name: 'Security' }).click();
  const remove = page.getByRole('form', { name: 'Delete account' });
  await remove.getByLabel('Type your email to confirm').fill(account.email);
  await remove.getByLabel('Master password').fill(account.password);
  await remove.getByLabel('Code from your app, or a recovery code').fill(recoveryCode);
  await remove.getByRole('button', { name: 'Delete account permanently' }).click();
  await expect(page.getByRole('status')).toContainText('were deleted');
  await page.getByLabel('Email').fill(account.email);
  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Log in' }).click();
  await expect(page.getByRole('alert')).toContainText('Incorrect email or master password');
});

test('imports a CSV and restores an encrypted backup into another account', async ({ page }) => {
  const { requests } = watch(page);
  const first = uniqueAccount();
  await signUp(page, first);
  await page.getByRole('button', { name: 'I’ve saved it' }).click();

  await page.getByRole('button', { name: 'Import / export' }).click();
  const importer = page.getByRole('region', { name: 'Import' });
  await importer.getByLabel('Choose a file to import').setInputFiles({
    name: 'bitwarden_export.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from(
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
        ',,login,GitLab,,,0,https://gitlab.com,E2E-IMPORT-USER,E2E-IMPORT-PW,\n' +
        ',,note,Secret note,text,,0,,,,\n',
    ),
  });
  await expect(importer.getByRole('status')).toContainText('Found 2 items in this Bitwarden file');
  await importer.getByRole('button', { name: 'Import 2 items' }).click();
  await expect(importer.getByText('Imported 2 items.')).toBeVisible();

  const exporter = page.getByRole('form', { name: 'Export' });
  await exporter.getByLabel('Master password').fill(first.password);
  const download = page.waitForEvent('download');
  await exporter.getByRole('button', { name: 'Download encrypted backup' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/^vaultx-backup-\d{4}-\d{2}-\d{2}\.json$/);
  const backupPath = await file.path();

  await page.getByRole('button', { name: 'Log out' }).click();
  const second = uniqueAccount();
  await signUp(page, second);
  await page.getByRole('button', { name: 'Import / export' }).click();
  await importer.getByLabel('Choose a file to import').setInputFiles(backupPath);
  await importer.getByLabel('Backup password').fill(first.password);
  await importer.getByRole('button', { name: 'Open backup' }).click();
  await importer.getByRole('button', { name: 'Import 2 items' }).click();
  await expect(importer.getByText('Imported 2 items.')).toBeVisible();
  await page.getByRole('button', { name: 'Back to vault' }).click();
  await expect(page.getByRole('listitem', { name: 'gitlab.com' })).toContainText('E2E-IMPORT-USER');

  for (const request of requests) {
    for (const secret of ['E2E-IMPORT-USER', 'E2E-IMPORT-PW', first.password]) {
      expect(request, `leaked "${secret}"`).not.toContain(secret);
    }
  }
});

// Passkeys need a real domain (WebAuthn refuses IP addresses as the RP ID), so
// this test opens the vault at localhost. The API under test must allow it:
// WEBAUTHN_RP_ID=localhost WEBAUTHN_ORIGINS=http://localhost:4173
test('adds a passkey, unlocks with it, and removes it', async ({ page }) => {
  const { requests } = watch(page);
  // Chrome's virtual authenticator: a platform passkey that verifies the user.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  const account = uniqueAccount();
  await signUp(page, account, 'http://localhost:4173/');
  await page.getByRole('button', { name: 'I’ve saved it' }).click();
  await addItem(page);

  await page.getByRole('button', { name: 'Security' }).click();
  const passkeys = page.getByRole('region', { name: 'Passkeys' });
  await passkeys.getByRole('button', { name: 'Add a passkey' }).click();
  const add = passkeys.getByRole('form', { name: 'Add a passkey' });
  await add.getByLabel('Passkey name').fill('E2E authenticator');
  await add.getByLabel('Master password').fill(account.password);
  await add.getByRole('button', { name: 'Create passkey' }).click();
  const codes = passkeys.getByRole('region', { name: 'Recovery codes' });
  await expect(codes.getByRole('listitem')).toHaveCount(10);
  await codes.getByRole('button', { name: 'I’ve saved them' }).click();
  await expect(passkeys.getByRole('listitem', { name: 'E2E authenticator' })).toBeVisible();
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials).toHaveLength(1);

  // Unlocking now asks for the passkey after the password; no code field.
  await page.getByRole('button', { name: 'Lock now' }).click();
  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Unlock' }).click();
  const second = page.getByRole('form', { name: 'Two-factor code' });
  await expect(second.getByLabel('Authentication code')).toHaveCount(0);
  await second.getByRole('button', { name: 'Use passkey' }).click();
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();

  // The assertion went to /login; the master password never did.
  const passkeyLogin = requests.find(
    (r) => r.startsWith('POST') && r.includes('/api/login') && r.includes('"webauthn"'),
  );
  expect(passkeyLogin).toBeDefined();
  for (const request of requests) expect(request).not.toContain(account.password);

  // Removing it takes the password and the passkey; afterwards the password alone unlocks.
  await page.getByRole('button', { name: 'Security' }).click();
  await passkeys.getByRole('button', { name: 'Remove' }).click();
  const remove = passkeys.getByRole('form', { name: 'Remove passkey' });
  await remove.getByLabel('Master password').fill(account.password);
  await remove.getByRole('button', { name: 'Remove passkey' }).click();
  await expect(passkeys.getByRole('button', { name: 'Add a passkey' })).toBeVisible();
  await expect(passkeys.getByRole('listitem')).toHaveCount(0);
  await page.getByRole('button', { name: 'Lock now' }).click();
  await page.getByLabel('Master password').fill(account.password);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('listitem', { name: ITEM.site })).toBeVisible();
});
