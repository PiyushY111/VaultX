import {
  MIN_KDF_PARAMS,
  encryptBackup,
  generateSalt,
  type KdfParams,
} from '@password-manager/crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { expectTyped, forEachCase, mutate, type Rng } from '../../test/fuzz';
import { toBase64 } from '../lib/base64';
import { CsvFormatError, parseCsv } from '../lib/csv';
import { BackupFormatError, WrongBackupPasswordError, readBackup } from './backup';
import { ImportFormatError, parseImport } from './importers';
import { derivePasswordKeys } from './kdf';

/**
 * Seeded randomized tests for everything that parses a file the user picked
 * (which could be anything): it returns a well-formed result or throws its
 * one documented error type, and quickly. Reproduce a failure with the
 * FUZZ_SEED it prints.
 */

/** RFC 4180 quoting, to check parseCsv round-trips. */
const csvField = (field: string) =>
  /[",\r\n]/.test(field) || field.startsWith('﻿') ? `"${field.replace(/"/g, '""')}"` : field;

describe('parseCsv', () => {
  it('returns rows of strings or throws CsvFormatError, for any text', async () => {
    await forEachCase('parseCsv/any', async (rng) => {
      const text = rng.bool(0.5) ? rng.string(200) : mutate(rng, 'a,b,"c ""d"""\r\n1,"2\n3",4\n');
      const result = await expectTyped(() => parseCsv(text), [CsvFormatError], text);
      if (result.ok) {
        for (const row of result.value) {
          expect(row.every((field) => typeof field === 'string')).toBe(true);
          expect(row.length === 1 && row[0] === '').toBe(false); // blank lines are skipped
        }
      }
    });
  });

  it('round-trips any table through RFC 4180 quoting', async () => {
    await forEachCase('parseCsv/roundtrip', async (rng) => {
      const width = 1 + rng.int(5);
      const rows = Array.from({ length: rng.int(6) }, () =>
        Array.from({ length: width }, () => rng.string(12)),
      ).filter((row) => !(row.length === 1 && row[0] === ''));
      const newline = rng.pick(['\n', '\r\n']);
      const text = rows.map((row) => row.map(csvField).join(',')).join(newline);
      expect(parseCsv(text)).toEqual(rows);
    });
  });

  it('is linear on large input', async () => {
    const big = `${'"x",'.repeat(200_000)}\n`.repeat(5);
    await expectTyped(() => parseCsv(big), [CsvFormatError], 'big csv', 2000);
    await expectTyped(
      () => parseCsv(`"${'a'.repeat(1_000_000)}`),
      [CsvFormatError],
      'open quote',
      2000,
    );
  });
});

const HEADERS = [
  'name',
  'title',
  'url',
  'login_uri',
  'website',
  'username',
  'login_username',
  'email',
  'password',
  'login_password',
  'note',
  'notes',
  'login_totp',
  'otpauth',
  'type',
  'folder',
  'httpRealm',
  'formActionOrigin',
  'Title',
  'URL',
  'extra',
];

function exportLike(rng: Rng): string {
  const headers = Array.from({ length: 1 + rng.int(7) }, () => rng.pick(HEADERS));
  const cell = () =>
    rng.pick([
      () => rng.string(15),
      () => rng.pick(['login', 'note', 'card', 'identity', 'securenote', '']),
      () => rng.pick(['https://example.com', 'example.com', 'http://[::1', 'ftp://x', '://', ' ']),
      () =>
        rng.pick(['JBSWY3DPEHPK3PXP', 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP', 'otpauth://%']),
    ])();
  const rows = Array.from({ length: rng.int(6) }, () =>
    Array.from({ length: rng.int(headers.length + 2) }, cell),
  );
  return [headers, ...rows].map((row) => row.map(csvField).join(',')).join('\n');
}

describe('parseImport', () => {
  it('returns well-formed items or throws ImportFormatError, for any file', async () => {
    await forEachCase('parseImport', async (rng) => {
      const text = rng.pick([
        () => exportLike(rng),
        () => mutate(rng, exportLike(rng)),
        () => rng.string(120),
      ])();
      const result = await expectTyped(() => parseImport(text), [ImportFormatError], text);
      if (!result.ok) return;
      const { items, skipped } = result.value;
      expect(Number.isInteger(skipped) && skipped >= 0).toBe(true);
      for (const item of items) {
        expect(item.site).not.toBe('');
        for (const field of [item.site, item.username, item.password, item.notes]) {
          expect(typeof field).toBe('string');
        }
        if (item.totp !== undefined) expect(typeof item.totp).toBe('string');
      }
    });
  });
});

describe('readBackup', () => {
  const PASSWORD = 'fuzz-BACKUP-password-1';
  const params: KdfParams = { ...MIN_KDF_PARAMS };
  let salt: Uint8Array;
  let key: Uint8Array;
  let valid: Record<string, unknown>;

  const fileWith = async (json: string) => {
    const { ciphertext, nonce } = await encryptBackup(json, key);
    return {
      format: 'vaultx-backup',
      version: 1,
      created_at: '2026-01-01T00:00:00.000Z',
      kdf: { salt: toBase64(salt), params },
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
    };
  };

  beforeAll(async () => {
    salt = await generateSalt();
    ({ stretchedMasterKey: key } = await derivePasswordKeys(PASSWORD, salt, params));
    valid = await fileWith(
      JSON.stringify({
        v: 1,
        items: [{ v: 1, site: 'example.com', username: 'u', password: 'p', notes: '' }],
      }),
    );
  });

  const allowed = [BackupFormatError, WrongBackupPasswordError];

  it('opens a valid backup', async () => {
    expect(await readBackup(JSON.stringify(valid), PASSWORD)).toEqual([
      { site: 'example.com', username: 'u', password: 'p', notes: '' },
    ]);
  });

  it('throws only its own errors for damaged or edited files', async () => {
    await forEachCase(
      'readBackup/file',
      async (rng) => {
        const edited: Record<string, unknown> = structuredClone(valid);
        const field = rng.pick(['format', 'version', 'kdf', 'nonce', 'ciphertext', 'created_at']);
        const text = rng.pick([
          () => mutate(rng, JSON.stringify(valid)),
          () => JSON.stringify({ ...edited, [field]: rng.json() }),
          () => {
            delete edited[field];
            return JSON.stringify(edited);
          },
          () =>
            JSON.stringify({
              ...edited,
              kdf: {
                salt: rng.pick([rng.json(), toBase64(salt)]),
                params: rng.pick([rng.json(), params]),
              },
            }),
          () => JSON.stringify(rng.json()),
          () => rng.string(80),
        ])();
        const result = await expectTyped(() => readBackup(text, PASSWORD), allowed, text, 10_000);
        if (result.ok) expect(Array.isArray(result.value)).toBe(true);
      },
      150,
    );
  });

  it('refuses flipped ciphertext bits as a wrong password', async () => {
    await forEachCase(
      'readBackup/bitflip',
      async (rng) => {
        const bytes = Uint8Array.from(atob(valid.ciphertext as string), (c) => c.charCodeAt(0));
        bytes[rng.int(bytes.length)]! ^= 1 << rng.int(8);
        const text = JSON.stringify({ ...valid, ciphertext: toBase64(bytes) });
        await expect(readBackup(text, PASSWORD)).rejects.toThrow(WrongBackupPasswordError);
      },
      10,
    );
  });

  it('checks the contents too: authentic but malformed plaintext is a BackupFormatError', async () => {
    await forEachCase(
      'readBackup/plaintext',
      async (rng) => {
        const plaintext = rng.pick([
          () => JSON.stringify(rng.json()),
          () => JSON.stringify({ v: 1, items: [rng.json(), rng.json()] }),
          () =>
            mutate(
              rng,
              '{"v":1,"items":[{"v":1,"site":"a","username":"","password":"","notes":""}]}',
            ),
          () => 'null',
        ])();
        const text = JSON.stringify(await fileWith(plaintext));
        await expectTyped(() => readBackup(text, PASSWORD), allowed, plaintext, 10_000);
      },
      25,
    );
  });
});
