import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_KDF_PARAMS,
  KEY_BYTES,
  MAX_KDF_MEMORY_COST,
  MIN_KDF_PARAMS,
  NONCE_BYTES,
  SALT_BYTES,
  TAG_BYTES,
} from '@password-manager/crypto';
import { describe, expect, it } from 'vitest';
import * as limits from '../src/limits.js';

const SRC_DIR = fileURLToPath(new URL('../src', import.meta.url));
const PACKAGE_JSON = fileURLToPath(new URL('../package.json', import.meta.url));

async function sourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) =>
      entry.isDirectory() ? sourceFiles(join(dir, entry.name)) : [join(dir, entry.name)],
    ),
  );
  return nested.flat().filter((file) => file.endsWith('.ts'));
}

describe('zero-knowledge boundary', () => {
  it('server source never imports the crypto package or libsodium', async () => {
    for (const file of await sourceFiles(SRC_DIR)) {
      const source = await readFile(file, 'utf8');
      expect(source, file).not.toMatch(
        /(?:from|import)\s*\(?\s*['"](?:@password-manager\/crypto|libsodium)/,
      );
    }
  });

  // The one exception is the two-factor secret: the server generates it,
  // holds it, and must read it to check codes, so it's encrypted at rest
  // under a server key (TOTP_ENCRYPTION_KEY). That is decryption of the
  // server's own data, never of anything a client encrypted.
  it('server source never calls a decrypt function, except decryptTotpSecret', async () => {
    for (const file of await sourceFiles(SRC_DIR)) {
      const source = (await readFile(file, 'utf8')).replace(
        /(?:decryptTotpSecret|TotpSecretDecryptionError)\s*\(/g,
        '',
      );
      expect(source, file).not.toMatch(/decrypt\w*\s*\(/i);
    }
  });

  it('only totp-secret-box.ts creates a decipher, and it reads no vault columns', async () => {
    for (const file of await sourceFiles(SRC_DIR)) {
      const source = await readFile(file, 'utf8');
      if (file.endsWith(join('src', 'totp-secret-box.ts'))) {
        expect(source).not.toMatch(/encrypted_vault_key|encrypted_data|encrypted_manifest/);
        continue;
      }
      expect(source, file).not.toMatch(/createDecipher/);
    }
  });

  it('the crypto package is a devDependency only (used by tests acting as the client)', async () => {
    const pkg = JSON.parse(await readFile(PACKAGE_JSON, 'utf8'));
    expect(pkg.dependencies ?? {}).not.toHaveProperty('@password-manager/crypto');
    expect(pkg.devDependencies).toHaveProperty('@password-manager/crypto');
  });
});

describe('server limits stay in sync with @password-manager/crypto', () => {
  it('byte lengths match', () => {
    expect(limits.KDF_SALT_BYTES).toBe(SALT_BYTES);
    expect(limits.NONCE_BYTES).toBe(NONCE_BYTES);
    expect(limits.TAG_BYTES).toBe(TAG_BYTES);
    expect(limits.AUTH_HASH_BYTES).toBe(KEY_BYTES);
    expect(limits.ENCRYPTED_VAULT_KEY_BYTES).toBe(KEY_BYTES + TAG_BYTES);
  });

  it('KDF bounds and defaults match', () => {
    expect(limits.KDF_LIMITS.memoryCost.min).toBe(MIN_KDF_PARAMS.memoryCost);
    expect(limits.KDF_LIMITS.memoryCost.max).toBe(MAX_KDF_MEMORY_COST);
    expect(limits.KDF_LIMITS.iterations.min).toBe(MIN_KDF_PARAMS.iterations);
    expect(limits.KDF_LIMITS.parallelism.min).toBe(MIN_KDF_PARAMS.parallelism);
    expect(limits.KDF_LIMITS.parallelism.max).toBe(MIN_KDF_PARAMS.parallelism);
    expect(limits.DEFAULT_KDF_PARAMS).toEqual(DEFAULT_KDF_PARAMS);
  });
});
