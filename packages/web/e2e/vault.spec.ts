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

async function signUp(page: Page, account: { email: string; password: string }) {
  await page.goto('/');
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
