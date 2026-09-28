import { randomBytes, randomUUID } from 'node:crypto';
import {
  MIN_KDF_PARAMS,
  decryptManifest,
  deriveKeys,
  deriveMasterKey,
  encryptItem,
  encryptManifest,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
  nextManifest,
  type EncryptedPayload,
  type ItemBinding,
  type ItemVersion,
  type KdfParams,
  type VaultManifest,
} from '@password-manager/crypto';
import type { FastifyInstance } from 'fastify';
import pg from 'pg';
import { expect, inject } from 'vitest';
import { buildApp } from '../src/app.js';
import type { Config } from '../src/config.js';
import { migrate } from '../src/migrate.js';
import { parseTotpKeyring } from '../src/totp-secret-box.js';
import { hotp, timeStep } from '../src/totp.js';

export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
export const unb64 = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64'));
export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** A fixed TOTP_ENCRYPTION_KEY value for tests (two keys, so decrypt-with-old paths exist). */
export const TEST_TOTP_KEY = Buffer.alloc(32, 0x5a).toString('base64');
export const TEST_TOTP_OLD_KEY = Buffer.alloc(32, 0xa5).toString('base64');
export const testTotpKeys = () => parseTotpKeyring(`${TEST_TOTP_KEY},${TEST_TOTP_OLD_KEY}`);

/** WebAuthn settings the tests' software authenticator signs for. */
export const TEST_WEBAUTHN = {
  rpId: 'vault.test',
  rpName: 'VaultX test',
  origins: ['https://vault.test'],
};

export interface TestContext {
  app: FastifyInstance;
  pool: pg.Pool;
  config: Config;
  close(): Promise<void>;
}

/** A fresh, migrated database and app instance, isolated from other test files. */
export async function createTestContext(
  overrides: Partial<Config> = {},
  { migrations = true } = {},
): Promise<TestContext> {
  const adminUrl = inject('adminDatabaseUrl');
  const dbName = `test_${randomBytes(8).toString('hex')}`;
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const url = new URL(adminUrl);
  url.pathname = `/${dbName}`;
  const pool = new pg.Pool({ connectionString: url.toString() });
  if (migrations) await migrate(pool);

  const config: Config = {
    host: '127.0.0.1',
    port: 0,
    logLevel: 'silent',
    trustProxy: false,
    sessionTtlSeconds: 3600,
    authRateLimitMax: 10_000,
    loginThrottle: { maxFailures: 5, windowSeconds: 900 },
    preloginSecret: Buffer.from('test-prelogin-secret'),
    preloginSecretIsEphemeral: false,
    totpKeys: testTotpKeys(),
    webauthn: TEST_WEBAUTHN,
    ...overrides,
  };
  const app = await buildApp({ pool, config, logger: false });
  await app.ready();

  return {
    app,
    pool,
    config,
    async close() {
      await app.close();
      await pool.end();
      const cleanup = new pg.Client({ connectionString: adminUrl });
      await cleanup.connect();
      await cleanup.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
      await cleanup.end();
    },
  };
}

/** Everything a real client holds after registering. None of it but the ciphertexts should reach the server. */
export interface ClientUser {
  email: string;
  password: string;
  salt: Uint8Array;
  kdfParams: KdfParams;
  masterKey: Uint8Array;
  stretchedMasterKey: Uint8Array;
  authHash: Uint8Array;
  vaultKey: Uint8Array;
  wrappedVaultKey: EncryptedPayload;
}

/** Performs the client side of registration using the real crypto package. */
export async function createClientUser(email: string, password: string): Promise<ClientUser> {
  const salt = await generateSalt();
  const kdfParams = { ...MIN_KDF_PARAMS };
  const masterKey = await deriveMasterKey(password, salt, kdfParams);
  const { stretchedMasterKey, authHash } = await deriveKeys(masterKey);
  const vaultKey = await generateVaultKey();
  const wrappedVaultKey = await encryptVaultKey(vaultKey, stretchedMasterKey);
  return {
    email,
    password,
    salt,
    kdfParams,
    masterKey,
    stretchedMasterKey,
    authHash,
    vaultKey,
    wrappedVaultKey,
  };
}

export function signupPayload(user: ClientUser) {
  return {
    email: user.email,
    auth_hash: b64(user.authHash),
    encrypted_vault_key: b64(user.wrappedVaultKey.ciphertext),
    vault_key_nonce: b64(user.wrappedVaultKey.nonce),
    kdf_salt: b64(user.salt),
    kdf_params: user.kdfParams,
  };
}

export async function signup(app: FastifyInstance, user: ClientUser) {
  return app.inject({ method: 'POST', url: '/signup', payload: signupPayload(user) });
}

export async function login(
  app: FastifyInstance,
  user: ClientUser,
  extra: { client?: string; headers?: Record<string, string> } = {},
): Promise<string> {
  const response = await app.inject({
    method: 'POST',
    url: '/login',
    headers: extra.headers ?? {},
    payload: {
      email: user.email,
      auth_hash: b64(user.authHash),
      ...(extra.client && { client: extra.client }),
    },
  });
  expect(response.statusCode, response.body).toBe(200);
  return response.json<{ token: string }>().token;
}

export async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  password: string,
): Promise<{ user: ClientUser; token: string }> {
  const user = await createClientUser(email, password);
  const response = await signup(app, user);
  expect(response.statusCode, response.body).toBe(201);
  return { user, token: await login(app, user) };
}

export interface ItemResponse {
  id: string;
  revision: number;
  encrypted_data: string;
  nonce: string;
  created_at: string;
  updated_at: string;
}

/** Ciphertext and nonce for an item, bound to its id and revision as a real client does. */
export async function encryptedItemPayload(
  plaintext: string,
  vaultKey: Uint8Array,
  binding: ItemBinding,
) {
  const { ciphertext, nonce } = await encryptItem(plaintext, vaultKey, binding);
  return { encrypted_data: b64(ciphertext), nonce: b64(nonce) };
}

// ---------------------------------------------------------------------------
// The vault manifest, computed the way a real client does

export interface ManifestBody {
  version: number;
  encrypted_data: string;
  nonce: string;
}

/** A well-formed manifest body for requests that must fail before it's looked at. */
export const PLACEHOLDER_MANIFEST: ManifestBody = {
  version: 1,
  encrypted_data: b64(new Uint8Array(32)),
  nonce: b64(new Uint8Array(24).fill(1)),
};

/** The account's current manifest, decrypted with the client's vault key (null if none yet). */
export async function currentManifest(
  app: FastifyInstance,
  token: string,
  vaultKey: Uint8Array,
): Promise<VaultManifest | null> {
  const response = await app.inject({ method: 'GET', url: '/vault-items', headers: bearer(token) });
  expect(response.statusCode, response.body).toBe(200);
  const { manifest } = response.json<{ manifest: ManifestBody | null }>();
  if (!manifest) return null;
  return decryptManifest(
    unb64(manifest.encrypted_data),
    unb64(manifest.nonce),
    vaultKey,
    manifest.version,
  );
}

export async function encryptManifestBody(
  manifest: VaultManifest,
  vaultKey: Uint8Array,
): Promise<ManifestBody> {
  const { ciphertext, nonce } = await encryptManifest(manifest, vaultKey);
  return { version: manifest.version, encrypted_data: b64(ciphertext), nonce: b64(nonce) };
}

/** The next manifest after `change`, encrypted: what a client sends with a write. */
export async function manifestFor(
  app: FastifyInstance,
  token: string,
  vaultKey: Uint8Array,
  change: { set?: ItemVersion[]; remove?: string[] },
): Promise<ManifestBody> {
  const current = await currentManifest(app, token, vaultKey);
  return encryptManifestBody(nextManifest(current, change, 'test'), vaultKey);
}

/**
 * A PUT body saving `plaintext` as the item's next revision. With `session`,
 * it carries the real next manifest; without, a placeholder (for requests
 * expected to fail on the item itself).
 */
export async function updatePayload(
  plaintext: string,
  vaultKey: Uint8Array,
  item: { id: string; revision: number },
  session?: { app: FastifyInstance; token: string },
) {
  const revision = item.revision + 1;
  return {
    revision,
    ...(await encryptedItemPayload(plaintext, vaultKey, { itemId: item.id, revision })),
    manifest: session
      ? await manifestFor(session.app, session.token, vaultKey, {
          set: [{ id: item.id, revision }],
        })
      : PLACEHOLDER_MANIFEST,
  };
}

/** Deletes an item the way a client does, with the next manifest. */
export async function deleteItem(
  app: FastifyInstance,
  token: string,
  vaultKey: Uint8Array,
  id: string,
) {
  return app.inject({
    method: 'DELETE',
    url: `/vault-items/${id}`,
    headers: bearer(token),
    payload: { manifest: await manifestFor(app, token, vaultKey, { remove: [id] }) },
  });
}

export async function createItem(
  app: FastifyInstance,
  token: string,
  vaultKey: Uint8Array,
  plaintext: string,
): Promise<ItemResponse> {
  const id = randomUUID();
  const response = await app.inject({
    method: 'POST',
    url: '/vault-items',
    headers: bearer(token),
    payload: {
      id,
      revision: 1,
      ...(await encryptedItemPayload(plaintext, vaultKey, { itemId: id, revision: 1 })),
      manifest: await manifestFor(app, token, vaultKey, { set: [{ id, revision: 1 }] }),
    },
  });
  expect(response.statusCode, response.body).toBe(201);
  return response.json<ItemResponse>();
}

/** Decodes an unpadded RFC 4648 base32 string, as an authenticator app would. */
export function base32Decode(base32Secret: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of base32Secret) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** The current TOTP code for a base32 secret, as an authenticator app would show it. */
export function totpCode(base32Secret: string, offsetSteps = 0): string {
  return hotp(base32Decode(base32Secret), timeStep(Date.now()) + offsetSteps);
}

export const bindingOf = (item: { id: string; revision: number }): ItemBinding => ({
  itemId: item.id,
  revision: item.revision,
});

// ---------------------------------------------------------------------------
// Raw-row scanning

export interface Secret {
  name: string;
  value: string | Uint8Array;
}

export interface Leak {
  table: string;
  column: string;
  secret: string;
  encoding: string;
}

/** The byte patterns a secret could appear as if the server stored it raw or re-encoded. */
function encodingsOf(secret: Secret): [string, Buffer][] {
  const raw =
    typeof secret.value === 'string'
      ? Buffer.from(secret.value, 'utf8')
      : Buffer.from(secret.value);
  return [
    ['raw', raw],
    ['base64', Buffer.from(raw.toString('base64'))],
    ['base64url', Buffer.from(raw.toString('base64url'))],
    ['hex', Buffer.from(raw.toString('hex'))],
  ];
}

function cellBytes(value: unknown): Buffer | null {
  if (value === null || value === undefined) return null;
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Date) return Buffer.from(value.toISOString());
  if (typeof value === 'object') return Buffer.from(JSON.stringify(value));
  return Buffer.from(String(value));
}

/** Every base table in the public schema, so new tables are scanned automatically. */
export async function listTables(pool: pg.Pool): Promise<string[]> {
  const { rows } = await pool.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`,
  );
  return rows.map((row) => row.table_name);
}

/** Reads every raw row of every table and reports any cell containing any secret in any encoding. */
export async function scanDatabaseForSecrets(pool: pg.Pool, secrets: Secret[]): Promise<Leak[]> {
  const leaks: Leak[] = [];
  const needles = secrets.flatMap((secret) =>
    encodingsOf(secret).map(([encoding, bytes]) => ({ secret: secret.name, encoding, bytes })),
  );
  for (const table of await listTables(pool)) {
    const { rows } = await pool.query<Record<string, unknown>>(`SELECT * FROM ${table}`);
    for (const row of rows) {
      for (const [column, value] of Object.entries(row)) {
        const haystack = cellBytes(value);
        if (!haystack) continue;
        for (const needle of needles) {
          if (haystack.includes(needle.bytes)) {
            leaks.push({ table, column, secret: needle.secret, encoding: needle.encoding });
          }
        }
      }
    }
  }
  return leaks;
}
