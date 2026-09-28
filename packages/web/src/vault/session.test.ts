import {
  decryptVaultKey,
  deriveKeys,
  deriveMasterKey,
  type KdfParams,
} from '@password-manager/crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { api } from '../api';
import { FAKE_TOTP_CODE, installFakeServer, type FakeServer } from '../../test/fakeServer';
import { fromBase64, toBase64 } from '../lib/base64';
import { decryptVaultItems, encryptNewItem, type VaultItem } from './items';
import { createRevisionLedger } from './revisionLedger';
import {
  SecondFactorRequiredError,
  WrongPasswordError,
  changeMasterPassword,
  logIn,
  proveCurrentPassword,
  signUp,
  type VaultSession,
} from './session';
import { VaultSync } from './sync';

const EMAIL = 'Alice@Example.com';
const PASSWORD = 'MASTER-correct-horse-battery-staple-41';
const ITEM = {
  site: 'bank-SITE-marker.example.com',
  username: 'alice-USERNAME-marker',
  password: 'ITEM-PASSWORD-marker-9x!',
  notes: 'NOTES-marker recovery codes 1111-2222',
};

let server: FakeServer;

beforeEach(() => {
  server = installFakeServer();
});

afterEach(() => {
  server.restore();
});

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** Everything the app sent, as one string per request. */
const wireTraffic = () =>
  server.requests.map((r) => `${r.method} ${r.url}\n${JSON.stringify(r.headers)}\n${r.body}`);

/** Adds an item the way the vault view does (with the next manifest). */
async function addItem(session: VaultSession, data = ITEM) {
  const sync = new VaultSync(session, createRevisionLedger(session.email, null));
  await sync.load();
  const item = await sync.create(data);
  return { sync, item };
}

describe('what crosses the network', () => {
  it('signup → add item → login → decrypt never sends the password, derived keys, vault key or plaintext', async () => {
    const session = await signUp(EMAIL, PASSWORD);
    await addItem(session);

    const again = await logIn(EMAIL, PASSWORD);
    const { items } = await api.listItems(again.token);
    const decrypted = await decryptVaultItems(items, again.vaultKey);
    expect(
      decrypted.items.map(({ site, username, password, notes }) => ({
        site,
        username,
        password,
        notes,
      })),
    ).toEqual([ITEM]);

    // Independently re-derive every secret from what was sent at signup.
    const signupBody = JSON.parse(server.requests.find((r) => r.url === '/api/signup')!.body);
    const masterKey = await deriveMasterKey(
      PASSWORD,
      fromBase64(signupBody.kdf_salt),
      signupBody.kdf_params as KdfParams,
    );
    const { stretchedMasterKey, authHash } = await deriveKeys(masterKey);
    const vaultKey = await decryptVaultKey(
      fromBase64(signupBody.encrypted_vault_key),
      fromBase64(signupBody.vault_key_nonce),
      stretchedMasterKey,
    );
    expect(vaultKey).toEqual(again.vaultKey);

    const forbidden: [string, string][] = [
      ['master password', PASSWORD],
      ...Object.entries(ITEM).map(([field, value]): [string, string] => [`item ${field}`, value]),
      ['master key (base64)', toBase64(masterKey)],
      ['master key (hex)', hex(masterKey)],
      ['stretched master key (base64)', toBase64(stretchedMasterKey)],
      ['stretched master key (hex)', hex(stretchedMasterKey)],
      ['vault key (base64)', toBase64(vaultKey)],
      ['vault key (hex)', hex(vaultKey)],
    ];
    for (const request of wireTraffic()) {
      for (const [name, value] of forbidden) {
        expect(request.includes(value), `${name} found in:\n${request}`).toBe(false);
      }
    }

    // The authHash is sent (that's its purpose), and only to /signup and /login.
    const authHashB64 = toBase64(authHash);
    const carriers = server.requests.filter((r) => r.body.includes(authHashB64)).map((r) => r.url);
    expect(carriers).toEqual(['/api/signup', '/api/login', '/api/login']);
  });

  it('sends exactly the documented fields to /signup and /login', async () => {
    await signUp(EMAIL, PASSWORD);
    const signup = JSON.parse(server.requests[0]!.body);
    expect(Object.keys(signup).sort()).toEqual(
      [
        'auth_hash',
        'email',
        'encrypted_vault_key',
        'kdf_params',
        'kdf_salt',
        'vault_key_nonce',
      ].sort(),
    );
    expect(signup.email).toBe('alice@example.com');
    expect(fromBase64(signup.auth_hash)).toHaveLength(32);
    expect(fromBase64(signup.encrypted_vault_key)).toHaveLength(48);
    expect(fromBase64(signup.vault_key_nonce)).toHaveLength(24);
    expect(fromBase64(signup.kdf_salt)).toHaveLength(16);
    expect(signup.kdf_params).toEqual({ memoryCost: 65536, iterations: 3, parallelism: 1 });

    const login = JSON.parse(server.requests[1]!.body);
    expect(Object.keys(login).sort()).toEqual(['auth_hash', 'client', 'email']);
    expect(login.client).toBe('web');
  });

  it('encrypts each item save with a fresh nonce', async () => {
    const session = await signUp(EMAIL, PASSWORD);
    const a = await encryptNewItem(ITEM, session.vaultKey);
    const b = await encryptNewItem(ITEM, session.vaultKey);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.encrypted_data).not.toBe(b.encrypted_data);
  });
});

describe('logIn', () => {
  it('rejects a wrong master password without sending it', async () => {
    await signUp(EMAIL, PASSWORD);
    await expect(logIn(EMAIL, 'wrong-password-123')).rejects.toThrow(
      'Incorrect email or master password',
    );
    expect(wireTraffic().some((r) => r.includes('wrong-password-123'))).toBe(false);
  });

  it('refuses KDF params below the security floor from a malicious server', async () => {
    await signUp(EMAIL, PASSWORD);
    server.users.get('alice@example.com')!.kdfParams = {
      memoryCost: 1024,
      iterations: 1,
      parallelism: 1,
    };
    await expect(logIn(EMAIL, PASSWORD)).rejects.toThrow(/kdfParams/);
    expect(
      server.requests.some((r) => r.url === '/api/login' && server.requests.indexOf(r) > 1),
    ).toBe(false);
  });
});

describe('signUp', () => {
  it('rejects a short master password before doing any network or crypto work', async () => {
    await expect(signUp(EMAIL, 'short')).rejects.toThrow(/at least 12/);
    expect(server.requests).toHaveLength(0);
  });
});

describe('changeMasterPassword', () => {
  const NEW_PASSWORD = 'NEW-master-password-orbit-lantern-58';

  async function signUpWithItem() {
    const session = await signUp(EMAIL, PASSWORD);
    const { sync, item } = await addItem(session);
    return { session, sync, items: [item] as VaultItem[] };
  }

  it('re-encrypts every item under a new vault key that only the new password unwraps', async () => {
    const { session, sync, items } = await signUpWithItem();
    const oldVaultKey = session.vaultKey;
    const oldKeyCopy = oldVaultKey.slice();
    const requestsBefore = server.requests.length;

    const changed = await changeMasterPassword(
      session,
      PASSWORD,
      NEW_PASSWORD,
      items,
      sync.currentManifest(),
    );
    expect(changed.items).toMatchObject([{ id: items[0]!.id, revision: 2, ...ITEM }]);
    expect(changed.manifest).toMatchObject({ items: { [items[0]!.id]: 2 } });
    expect(oldVaultKey.every((byte) => byte === 0)).toBe(true);
    expect(session.vaultKey).not.toEqual(oldKeyCopy);

    // Nothing secret went over the wire for the change.
    const sent = wireTraffic().slice(requestsBefore).join('\n');
    for (const value of [PASSWORD, NEW_PASSWORD, ...Object.values(ITEM)]) {
      expect(sent).not.toContain(value);
    }
    expect(sent).not.toContain(toBase64(session.vaultKey));

    await expect(logIn(EMAIL, PASSWORD)).rejects.toThrow('Incorrect email or master password');
    const again = await logIn(EMAIL, NEW_PASSWORD);
    expect(again.vaultKey).toEqual(session.vaultKey);
    const { items: stored } = await api.listItems(again.token);
    const decrypted = await decryptVaultItems(stored, again.vaultKey);
    expect(decrypted.failedIds).toEqual([]);
    expect(decrypted.items).toMatchObject([ITEM]);
    // Anything still encrypted under the old key would fail to open now.
    expect((await decryptVaultItems(stored, oldKeyCopy)).failedIds).toHaveLength(1);
    // The manifest was re-encrypted too: a fresh load finds nothing wrong.
    const reloaded = await new VaultSync(again, createRevisionLedger(EMAIL, null)).load();
    expect(reloaded.warnings).toEqual({
      failedIds: [],
      rolledBackIds: [],
      missingIds: [],
      unexpectedIds: [],
      manifest: null,
    });
  });

  it('refuses a wrong current password locally, without sending anything', async () => {
    const { session, sync, items } = await signUpWithItem();
    const requestsBefore = server.requests.length;
    await expect(
      changeMasterPassword(
        session,
        'wrong-password-123',
        NEW_PASSWORD,
        items,
        sync.currentManifest(),
      ),
    ).rejects.toThrow(WrongPasswordError);
    expect(
      server.requests.slice(requestsBefore).map((request) => `${request.method} ${request.url}`),
    ).toEqual(['GET /api/vault-key']);
    expect(session.vaultKey.some((byte) => byte !== 0)).toBe(true);
    expect((await logIn(EMAIL, PASSWORD)).email).toBe('alice@example.com');
  });

  it('changes nothing if the item list is out of date', async () => {
    const { session, sync, items } = await signUpWithItem();
    const keyBefore = session.vaultKey.slice();
    await expect(
      changeMasterPassword(session, PASSWORD, NEW_PASSWORD, [], sync.currentManifest()),
    ).rejects.toThrow(/vault changed/);
    expect(session.vaultKey).toEqual(keyBefore);
    expect((await logIn(EMAIL, PASSWORD)).vaultKey).toEqual(keyBefore);
    expect(items).toHaveLength(1);
  });
});

describe('two-factor login', () => {
  async function enableTwoFactor() {
    const session = await signUp(EMAIL, PASSWORD);
    await api.setupTotp(session.token);
    const { recovery_codes } = await api.enableTotp(session.token, {
      current_auth_hash: await proveCurrentPassword(session, PASSWORD),
      totp_code: FAKE_TOTP_CODE,
    });
    return recovery_codes;
  }

  it('asks for a code after the password, without deriving keys again', async () => {
    await enableTwoFactor();
    const pending = await logIn(EMAIL, PASSWORD).catch((error: unknown) => error);
    expect(pending).toBeInstanceOf(SecondFactorRequiredError);
    const preloginsBefore = server.requests.filter((r) => r.url === '/api/prelogin').length;

    await expect(
      (pending as SecondFactorRequiredError).complete({ totp_code: '000000' }),
    ).rejects.toThrow(/incorrect/);
    const session = await (pending as SecondFactorRequiredError).complete({
      totp_code: FAKE_TOTP_CODE,
    });
    expect(session.email).toBe('alice@example.com');
    // Same keys, no second prelogin/Argon2id run; the code went only to /login.
    expect(server.requests.filter((r) => r.url === '/api/prelogin')).toHaveLength(preloginsBefore);
    // Done: it can't be used again.
    await expect(
      (pending as SecondFactorRequiredError).complete({ totp_code: FAKE_TOTP_CODE }),
    ).rejects.toThrow(/expired/);
  });

  it('accepts a recovery code instead', async () => {
    const [code] = await enableTwoFactor();
    const pending = (await logIn(EMAIL, PASSWORD).catch(
      (e: unknown) => e,
    )) as SecondFactorRequiredError;
    expect((await pending.complete({ recovery_code: code! })).email).toBe('alice@example.com');
  });
});

describe('proveCurrentPassword', () => {
  it('refuses a wrong password before sending anything', async () => {
    const session = await signUp(EMAIL, PASSWORD);
    const before = server.requests.length;
    await expect(proveCurrentPassword(session, 'wrong-password-123')).rejects.toThrow(
      WrongPasswordError,
    );
    expect(server.requests.slice(before).map((r) => r.url)).toEqual(['/api/vault-key']);
  });
});
