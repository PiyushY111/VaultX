import { randomBytes } from 'node:crypto';
import {
  MIN_KDF_PARAMS,
  deriveKeys,
  deriveMasterKey,
  encryptItem,
  encryptVaultKey,
  generateSalt,
  generateVaultKey,
  type EncryptedPayload,
  type KdfParams,
} from '@password-manager/crypto';
import type { FastifyInstance } from 'fastify';
import pg from 'pg';
import { expect, inject } from 'vitest';
import { buildApp } from '../src/app.js';
import type { Config } from '../src/config.js';
import { migrate } from '../src/migrate.js';

export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
export const unb64 = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64'));
export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

export interface TestContext {
  app: FastifyInstance;
  pool: pg.Pool;
  config: Config;
  close(): Promise<void>;
}

/** A fresh, migrated database and app instance, isolated from other test files. */
export async function createTestContext(overrides: Partial<Config> = {}): Promise<TestContext> {
  const adminUrl = inject('adminDatabaseUrl');
  const dbName = `test_${randomBytes(8).toString('hex')}`;
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const url = new URL(adminUrl);
  url.pathname = `/${dbName}`;
  const pool = new pg.Pool({ connectionString: url.toString() });
  await migrate(pool);

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

export async function login(app: FastifyInstance, user: ClientUser): Promise<string> {
  const response = await app.inject({
    method: 'POST',
    url: '/login',
    payload: { email: user.email, auth_hash: b64(user.authHash) },
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
  encrypted_data: string;
  nonce: string;
  created_at: string;
  updated_at: string;
}

export async function encryptedItemPayload(plaintext: string, vaultKey: Uint8Array) {
  const { ciphertext, nonce } = await encryptItem(plaintext, vaultKey);
  return { encrypted_data: b64(ciphertext), nonce: b64(nonce) };
}

export async function createItem(
  app: FastifyInstance,
  token: string,
  vaultKey: Uint8Array,
  plaintext: string,
): Promise<ItemResponse> {
  const response = await app.inject({
    method: 'POST',
    url: '/vault-items',
    headers: bearer(token),
    payload: await encryptedItemPayload(plaintext, vaultKey),
  });
  expect(response.statusCode, response.body).toBe(201);
  return response.json<ItemResponse>();
}

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
