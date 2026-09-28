import { createHmac } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_KDF_PARAMS,
  decryptItem,
  decryptManifest,
  deriveKeys,
  deriveMasterKey,
  encryptItem,
  encryptManifest,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
  nextManifest,
} from '@password-manager/crypto';
import { test as base, chromium, expect, type BrowserContext, type Page } from '@playwright/test';

const API_URL = process.env.API_URL ?? 'http://127.0.0.1:3000';
const EXTENSION_PATH = fileURLToPath(new URL('../dist', import.meta.url));
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, 'base64'));

// --- A local site with a login form ------------------------------------------

const LOGIN_PAGE = `<!doctype html><title>Test login</title><h1>Sign in</h1>
<form method="post" action="/welcome">
  <label>Username <input id="username" name="username" type="text" autocomplete="username"></label>
  <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
  <button type="submit">Sign in</button>
</form>`;

const TWO_FACTOR_PAGE = `<!doctype html><title>Two-factor</title><h1>Enter your code</h1>
<form method="post" action="/welcome">
  <label>Authentication code <input id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric"></label>
  <button type="submit">Verify</button>
</form>`;

let site: Server;
let sitePort: number;

base.beforeAll(async () => {
  site = createServer((request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end(
      request.url?.startsWith('/welcome')
        ? '<!doctype html><title>Welcome</title><h1>Welcome</h1>'
        : request.url?.startsWith('/2fa')
          ? TWO_FACTOR_PAGE
          : LOGIN_PAGE,
    );
  });
  await new Promise<void>((resolve) => site.listen(0, '127.0.0.1', resolve));
  sitePort = (site.address() as AddressInfo).port;
});

base.afterAll(async () => {
  await new Promise((resolve) => site.close(resolve));
});

// --- An account created the way the web vault does ---------------------------

interface Account {
  email: string;
  password: string;
  authHash: string;
  vaultKey: Uint8Array;
}

async function api<T>(
  path: string,
  init: { method?: string; body?: unknown; token?: string } = {},
): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    method: init.method ?? (init.body ? 'POST' : 'GET'),
    headers: {
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...(init.token ? { authorization: `Bearer ${init.token}` } : {}),
    },
    ...(init.body ? { body: JSON.stringify(init.body) } : {}),
  });
  if (!response.ok) throw new Error(`${path}: ${response.status} ${await response.text()}`);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function createAccount(): Promise<Account> {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const email = `ext-e2e-${id}@example.com`;
  const password = `EXT-MASTER-${id}`;
  const salt = await generateSalt();
  const { stretchedMasterKey, authHash } = await deriveKeys(
    await deriveMasterKey(password, salt, DEFAULT_KDF_PARAMS),
  );
  const vaultKey = await generateVaultKey();
  const wrapped = await encryptVaultKey(vaultKey, stretchedMasterKey);
  await api('/signup', {
    body: {
      email,
      auth_hash: b64(authHash),
      encrypted_vault_key: b64(wrapped.ciphertext),
      vault_key_nonce: b64(wrapped.nonce),
      kdf_salt: b64(salt),
      kdf_params: DEFAULT_KDF_PARAMS,
    },
  });
  const account = { email, password, authHash: b64(authHash), vaultKey };
  // Like the web vault's signup: the new account's first (empty) manifest,
  // so the extension has a trusted baseline and doesn't ask for one.
  const first = await encryptManifest(nextManifest(null, {}, 'web'), vaultKey);
  await api('/vault-manifest', {
    method: 'PUT',
    token: await apiToken(account),
    body: { version: 1, encrypted_data: b64(first.ciphertext), nonce: b64(first.nonce) },
  });
  return account;
}

async function apiToken(account: Account): Promise<string> {
  return (
    await api<{ token: string }>('/login', {
      body: { email: account.email, auth_hash: account.authHash },
    })
  ).token;
}

async function addItem(
  account: Account,
  data: { site: string; username: string; password: string; totp?: string },
) {
  const id = crypto.randomUUID();
  const token = await apiToken(account);
  const { ciphertext, nonce } = await encryptItem(
    JSON.stringify({ v: 1, ...data, notes: '' }),
    account.vaultKey,
    { itemId: id, revision: 1 },
  );
  // Like a real client, the write carries the vault's next manifest.
  const { manifest: stored } = await api<{
    manifest: { version: number; encrypted_data: string; nonce: string } | null;
  }>('/vault-items', { token });
  const current = stored
    ? await decryptManifest(
        unb64(stored.encrypted_data),
        unb64(stored.nonce),
        account.vaultKey,
        stored.version,
      )
    : null;
  const next = nextManifest(current, { set: [{ id, revision: 1 }] }, 'e2e');
  const encrypted = await encryptManifest(next, account.vaultKey);
  await api('/vault-items', {
    token,
    body: {
      id,
      revision: 1,
      encrypted_data: b64(ciphertext),
      nonce: b64(nonce),
      manifest: {
        version: next.version,
        encrypted_data: b64(encrypted.ciphertext),
        nonce: b64(encrypted.nonce),
      },
    },
  });
}

async function listItems(account: Account) {
  const { items } = await api<{
    items: { id: string; revision: number; encrypted_data: string; nonce: string }[];
  }>('/vault-items', {
    token: await apiToken(account),
  });
  const raw = JSON.stringify(items);
  const decrypted = await Promise.all(
    items.map(async (item) =>
      JSON.parse(
        await decryptItem(unb64(item.encrypted_data), unb64(item.nonce), account.vaultKey, {
          itemId: item.id,
          revision: item.revision,
        }),
      ),
    ),
  );
  return { raw, decrypted };
}

// --- Browser with the extension loaded ---------------------------------------

async function launch(
  userDataDir: string,
): Promise<{ context: BrowserContext; extensionId: string }> {
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
  });
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  return { context, extensionId: new URL(worker.url()).host };
}

const test = base.extend<{ userDataDir: string }>({
  // eslint-disable-next-line no-empty-pattern
  userDataDir: async ({}, use) => {
    const dir = await mkdtemp(join(tmpdir(), 'pm-ext-e2e-'));
    await use(dir);
    await rm(dir, { recursive: true, force: true });
  },
});

async function openPopup(context: BrowserContext, extensionId: string): Promise<Page> {
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  return popup;
}

async function unlockInPopup(popup: Page, account: Account) {
  await popup.getByRole('button', { name: 'Settings' }).click();
  await popup.getByLabel('Server URL').fill(API_URL);
  await popup.getByRole('button', { name: 'Save' }).click();
  await popup.getByLabel('Email').fill(account.email);
  await popup.getByLabel('Master password').fill(account.password);
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByText(`Unlocked as ${account.email}`)).toBeVisible();
}

// The in-page prompt is in a *closed* shadow root, so neither page scripts nor
// Playwright selectors can reach it. Use the DevTools protocol (which can
// pierce it) to locate elements, then click with the real mouse so the event
// is trusted, exactly like a user's click.
interface DomNode {
  nodeId: number;
  nodeName: string;
  nodeValue?: string;
  children?: DomNode[];
  shadowRoots?: DomNode[];
}

async function promptNodes(
  page: Page,
): Promise<{ text: string; buttons: Map<string, number> } | null> {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { root } = (await cdp.send('DOM.getDocument', { depth: -1, pierce: true })) as {
      root: DomNode;
    };
    const find = (node: DomNode): DomNode | null =>
      node.nodeName === 'VAULTX-PROMPT'
        ? node
        : ([...(node.children ?? []), ...(node.shadowRoots ?? [])].map(find).find(Boolean) ?? null);
    const host = find(root);
    if (!host) return null;
    const text: string[] = [];
    const buttons = new Map<string, number>();
    const walk = (node: DomNode) => {
      if (node.nodeName === '#text' && node.nodeValue) text.push(node.nodeValue);
      if (node.nodeName === 'BUTTON')
        buttons.set((node.children ?? []).map((c) => c.nodeValue ?? '').join(''), node.nodeId);
      [...(node.children ?? []), ...(node.shadowRoots ?? [])].forEach(walk);
    };
    walk(host);
    const joined = text.filter((t) => !t.includes('{')).join(' ');
    return { text: joined, buttons };
  } finally {
    await cdp.detach();
  }
}

async function expectPrompt(page: Page, text: string | RegExp): Promise<void> {
  await expect
    .poll(async () => (await promptNodes(page))?.text ?? '', { timeout: 10_000 })
    .toMatch(text);
}

async function clickPromptButton(page: Page, label: string): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  try {
    const nodeId = (await promptNodes(page))?.buttons.get(label);
    if (!nodeId) throw new Error(`No "${label}" button in prompt`);
    // Node ids are per-session; re-resolve through this session.
    const { root } = (await cdp.send('DOM.getDocument', { depth: -1, pierce: true })) as {
      root: DomNode;
    };
    const matches: DomNode[] = [];
    const walk = (node: DomNode) => {
      if (
        node.nodeName === 'BUTTON' &&
        (node.children ?? []).map((c) => c.nodeValue ?? '').join('') === label
      )
        matches.push(node);
      [...(node.children ?? []), ...(node.shadowRoots ?? [])].forEach(walk);
    };
    walk(root);
    const { model } = (await cdp.send('DOM.getBoxModel', { nodeId: matches[0]!.nodeId })) as {
      model: { content: number[] };
    };
    const [x1, y1, , , x3, y3] = model.content as [number, number, number, number, number, number];
    await page.mouse.click((x1 + x3) / 2, (y1 + y3) / 2);
  } finally {
    await cdp.detach();
  }
}

// --- Tests -------------------------------------------------------------------

test('unlock → view → autofill → save a new login → lock', async ({ userDataDir }) => {
  const account = await createAccount();
  await addItem(account, {
    site: '127.0.0.1',
    username: 'e2e-user',
    password: 'E2E-SEEDED-PASSWORD',
  });
  const { context, extensionId } = await launch(userDataDir);

  // Record everything the extension sends to the API.
  const apiTraffic: string[] = [];
  context.on('request', (request) => {
    if (request.url().startsWith(API_URL))
      apiTraffic.push(`${request.url()} ${request.postData() ?? ''}`);
  });

  try {
    // 1. Unlock in the popup and view saved logins.
    const popup = await openPopup(context, extensionId);
    await unlockInPopup(popup, account);
    const item = popup.getByRole('listitem', { name: '127.0.0.1' });
    await expect(item).toContainText('e2e-user');
    await item.getByRole('button', { name: 'Show' }).click();
    await expect(item).toContainText('E2E-SEEDED-PASSWORD');

    // 2. Autofill on the matching site — only after clicking "Fill".
    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${sitePort}/login`);
    await expectPrompt(page, /Fill saved login\?.*e2e-user/);
    await expect(page.locator('#password')).toHaveValue('');
    // Page scripts can't reach into the prompt.
    expect(
      await page.evaluate(() => document.querySelector('vaultx-prompt')?.shadowRoot ?? null),
    ).toBeNull();
    await clickPromptButton(page, 'Fill');
    await expect(page.locator('#username')).toHaveValue('e2e-user');
    await expect(page.locator('#password')).toHaveValue('E2E-SEEDED-PASSWORD');

    // 3. A different site (localhost ≠ 127.0.0.1) gets no offer; submitting a
    //    new login there prompts to save it after the redirect.
    const other = await context.newPage();
    await other.goto(`http://localhost:${sitePort}/login`);
    await other.waitForTimeout(1_000);
    expect(await promptNodes(other)).toBeNull();
    await other.locator('#username').fill('new-user');
    await other.locator('#password').fill('E2E-NEW-SITE-PASSWORD');
    await other.getByRole('button', { name: 'Sign in' }).click();
    await expect(other.getByRole('heading', { name: 'Welcome' })).toBeVisible();
    await expectPrompt(other, /Save this password\?.*new-user on localhost/);
    await clickPromptButton(other, 'Save');
    await expect.poll(async () => (await promptNodes(other)) === null).toBe(true);

    const { raw, decrypted } = await listItems(account);
    expect(decrypted.map((i) => [i.site, i.username, i.password])).toEqual([
      ['127.0.0.1', 'e2e-user', 'E2E-SEEDED-PASSWORD'],
      ['localhost', 'new-user', 'E2E-NEW-SITE-PASSWORD'],
    ]);
    expect(raw).not.toContain('E2E-NEW-SITE-PASSWORD');

    // 4. Lock: pages now get a "locked" notice instead of an offer.
    await popup.bringToFront();
    await popup.reload();
    await popup.getByRole('button', { name: 'Lock' }).click();
    await expect(popup.getByRole('button', { name: 'Unlock' })).toBeVisible();
    await page.goto(`http://127.0.0.1:${sitePort}/login`);
    await expectPrompt(page, /VaultX is locked/);

    // Nothing sensitive went over the wire.
    expect(apiTraffic.length).toBeGreaterThan(3);
    for (const entry of apiTraffic) {
      for (const secret of [
        account.password,
        'E2E-SEEDED-PASSWORD',
        'E2E-NEW-SITE-PASSWORD',
        'new-user',
      ]) {
        expect(entry).not.toContain(secret);
      }
    }
  } finally {
    await context.close();
  }
});

test('the vault is locked again after the browser restarts', async ({ userDataDir }) => {
  const account = await createAccount();
  let { context, extensionId } = await launch(userDataDir);
  const popup = await openPopup(context, extensionId);
  await unlockInPopup(popup, account);
  await context.close();

  ({ context, extensionId } = await launch(userDataDir));
  try {
    const reopened = await openPopup(context, extensionId);
    await expect(reopened.getByRole('button', { name: 'Unlock' })).toBeVisible();
    // The non-secret email and server URL are remembered for convenience.
    await expect(reopened.getByLabel('Email')).toHaveValue(account.email);
    await expect(reopened.getByText(`Server: ${API_URL}`)).toBeVisible();
  } finally {
    await context.close();
  }
});

test('clears a password copied in the popup after 30 seconds, even once the popup is closed', async ({
  userDataDir,
}) => {
  test.setTimeout(120_000);
  const account = await createAccount();
  await addItem(account, {
    site: 'clip.example.com',
    username: 'u',
    password: 'E2E-CLIP-PASSWORD',
  });
  const { context, extensionId } = await launch(userDataDir);
  try {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const popup = await openPopup(context, extensionId);
    await unlockInPopup(popup, account);
    const readClipboard = () => popup.evaluate(() => navigator.clipboard.readText());
    await popup
      .getByRole('listitem', { name: 'clip.example.com' })
      .getByRole('button', { name: 'Copy password' })
      .click();
    await expect.poll(readClipboard).toBe('E2E-CLIP-PASSWORD');

    // Close the popup, as a user would; the background clears it on its own.
    await popup.close();
    const reader = await openPopup(context, extensionId);
    await expect
      .poll(() => reader.evaluate(() => navigator.clipboard.readText()), {
        timeout: 60_000,
        intervals: [2_000],
      })
      .toBe('');
  } finally {
    await context.close();
  }
});

test('asks in the popup before trusting a vault whose manifest can’t be verified', async ({
  userDataDir,
}) => {
  const account = await createAccount();
  await addItem(account, { site: 'kept.example.com', username: 'me', password: 'pw' });
  // The server now holds a manifest that doesn't open with the vault key
  // (the server itself can't tell): the extension has nothing to trust.
  const token = await apiToken(account);
  const bogus = await encryptManifest(nextManifest(null, {}, 'attacker'), await generateVaultKey());
  await api('/vault-manifest', {
    method: 'PUT',
    token,
    body: { version: 3, encrypted_data: b64(bogus.ciphertext), nonce: b64(bogus.nonce) },
  });
  const version = async () =>
    (await api<{ manifest: { version: number } }>('/vault-items', { token })).manifest.version;

  const { context, extensionId } = await launch(userDataDir);
  try {
    const popup = await openPopup(context, extensionId);
    await unlockInPopup(popup, account);
    const box = popup.getByRole('region', { name: 'Confirm this vault' });
    await expect(box).toContainText('Use this as the trusted baseline?');
    await expect(box).toContainText('1 item');
    await expect(popup.getByRole('button', { name: 'Add login' })).toBeDisabled();
    // Unlocking and listing wrote nothing.
    expect(await version()).toBe(3);

    await box.getByRole('button', { name: 'Use as trusted baseline' }).click();
    await expect(popup.getByRole('region', { name: 'Confirm this vault' })).toBeHidden();
    await expect(popup.getByRole('button', { name: 'Add login' })).toBeEnabled();
    expect(await version()).toBe(4);
    // The new baseline opens with the real key and lists the item.
    const { decrypted } = await listItems(account);
    expect(decrypted.map((item) => item.site)).toEqual(['kept.example.com']);
  } finally {
    await context.close();
  }
});

test('adds a login from the popup, encrypted before it is sent', async ({ userDataDir }) => {
  const account = await createAccount();
  const { context, extensionId } = await launch(userDataDir);
  const apiTraffic: string[] = [];
  context.on('request', (request) => {
    if (request.url().startsWith(API_URL)) apiTraffic.push(request.postData() ?? '');
  });
  try {
    const popup = await openPopup(context, extensionId);
    await unlockInPopup(popup, account);
    await popup.getByRole('button', { name: 'Add login' }).click();
    const form = popup.getByRole('form', { name: 'Add login' });
    await form.getByLabel('Site').fill('popup-added.example.com');
    await form.getByLabel('Username').fill('popup-user');
    await form.getByRole('button', { name: 'Generate' }).click();
    const generated = await form.getByLabel('Password').inputValue();
    expect(generated).toHaveLength(20);
    await form.getByLabel('Notes').fill('POPUP-NOTES');
    await form.getByRole('button', { name: 'Save' }).click();

    await expect(popup.getByRole('listitem', { name: 'popup-added.example.com' })).toContainText(
      'popup-user',
    );
    const { decrypted } = await listItems(account);
    expect(decrypted).toMatchObject([
      { site: 'popup-added.example.com', username: 'popup-user', password: generated },
    ]);
    for (const secret of [generated, 'popup-user', 'POPUP-NOTES']) {
      expect(apiTraffic.join('\n')).not.toContain(secret);
    }
  } finally {
    await context.close();
  }
});

/** RFC 6238 TOTP for a base32 secret, as an authenticator app computes it. */
function totp(base32: string, now = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30_000)));
  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest[19]! & 0x0f;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

test('unlocks with a two-factor code in the popup', async ({ userDataDir }) => {
  const account = await createAccount();
  await addItem(account, { site: '2fa.example.com', username: 'u', password: 'E2E-2FA-PW' });
  const token = await apiToken(account);
  const { secret } = await api<{ secret: string }>('/account/totp/setup', {
    method: 'POST',
    token,
  });
  await api('/account/totp/enable', {
    token,
    body: { current_auth_hash: account.authHash, totp_code: totp(secret) },
  });

  const { context, extensionId } = await launch(userDataDir);
  try {
    const popup = await openPopup(context, extensionId);
    await popup.getByRole('button', { name: 'Settings' }).click();
    await popup.getByLabel('Server URL').fill(API_URL);
    await popup.getByRole('button', { name: 'Save' }).click();
    await popup.getByLabel('Email').fill(account.email);
    await popup.getByLabel('Master password').fill(account.password);
    await popup.getByRole('button', { name: 'Unlock' }).click();

    const form = popup.getByRole('form', { name: 'Two-factor code' });
    await form.getByLabel('Authentication code').fill('000000');
    await form.getByRole('button', { name: 'Verify' }).click();
    await expect(form.getByRole('alert')).toContainText('incorrect');
    // The code used to turn it on can't be reused; the next step's can.
    await form.getByLabel('Authentication code').fill(totp(secret, Date.now() + 30_000));
    await form.getByRole('button', { name: 'Verify' }).click();
    await expect(popup.getByText(`Unlocked as ${account.email}`)).toBeVisible();
    await expect(popup.getByRole('listitem', { name: '2fa.example.com' })).toBeVisible();
    await expect(popup.getByRole('alert', { name: 'Vault warnings' })).toBeHidden();
  } finally {
    await context.close();
  }
});

test('fills a two-factor code on the site’s 2FA page, after a click', async ({ userDataDir }) => {
  const account = await createAccount();
  const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  await addItem(account, { site: '127.0.0.1', username: 'mfa-user', password: 'pw', totp: SECRET });
  const { context, extensionId } = await launch(userDataDir);
  try {
    const popup = await openPopup(context, extensionId);
    await unlockInPopup(popup, account);
    // The popup shows the live code for the login.
    const row = popup.getByRole('listitem', { name: '127.0.0.1' });
    await expect(row.getByLabel('Two-factor code')).toHaveText(/^\d{3} \d{3}$/);

    const page = await context.newPage();
    await page.goto(`http://127.0.0.1:${sitePort}/2fa`);
    await expectPrompt(page, /Fill two-factor code\?.*mfa-user/);
    await expect(page.locator('#otp')).toHaveValue('');
    await clickPromptButton(page, 'Fill code');
    await expect(page.locator('#otp')).toHaveValue(totp(SECRET));
  } finally {
    await context.close();
  }
});
