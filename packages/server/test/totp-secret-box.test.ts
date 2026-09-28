import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import {
  ENCRYPTED_TOTP_SECRET_BYTES,
  TotpSecretDecryptionError,
  decryptTotpSecret,
  encryptTotpSecret,
  isCurrentTotpCiphertext,
  parseTotpKeyring,
  totpKeyId,
} from '../src/totp-secret-box.js';

const KEY_A = Buffer.alloc(32, 0x11).toString('base64');
const KEY_B = Buffer.alloc(32, 0x22).toString('base64');
const SECRET = Buffer.from('12345678901234567890');

describe('parseTotpKeyring', () => {
  it('uses the first key to encrypt and accepts all of them to decrypt', () => {
    const keyring = parseTotpKeyring(`${KEY_A}, ${KEY_B}`);
    expect(keyring.primary.key).toEqual(Buffer.from(KEY_A, 'base64'));
    expect([...keyring.byId.keys()]).toEqual([
      totpKeyId(Buffer.from(KEY_A, 'base64')),
      totpKeyId(Buffer.from(KEY_B, 'base64')),
    ]);
  });

  it('derives key ids from the key, so reordering during rotation keeps them', () => {
    const before = parseTotpKeyring(KEY_A);
    const after = parseTotpKeyring(`${KEY_B},${KEY_A}`);
    expect(after.byId.get(before.primary.id)).toEqual(before.primary.key);
    expect(after.primary.id).not.toBe(before.primary.id);
  });

  it.each([
    ['unset', undefined, /not set/],
    ['empty', '', /not set/],
    ['blank', '   ', /not set/],
    ['not base64', 'not-a-key', /key #1 must be exactly 32 bytes/],
    ['too short', Buffer.alloc(16, 1).toString('base64'), /key #1 must be exactly 32 bytes/],
    ['too long', Buffer.alloc(33, 1).toString('base64'), /key #1 must be exactly 32 bytes/],
    ['unpadded', KEY_A.replace('=', ''), /key #1 must be exactly 32 bytes/],
    ['a trailing comma', `${KEY_A},`, /key #2 must be exactly 32 bytes/],
    ['a bad second key', `${KEY_A},${KEY_B.slice(1)}`, /key #2 must be exactly 32 bytes/],
    ['an all-zero key', Buffer.alloc(32).toString('base64'), /all zero/],
    ['the same key twice', `${KEY_A},${KEY_A}`, /same key twice/],
  ])('rejects %s', (_, raw, message) => {
    expect(() => parseTotpKeyring(raw)).toThrow(message);
  });

  it('never puts key material in its error messages', () => {
    const almost = Buffer.alloc(31, 0x77).toString('base64');
    let message = '';
    try {
      parseTotpKeyring(`${KEY_A},${almost}`);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/key #2/);
    expect(message).not.toContain(almost);
    expect(message).not.toContain(KEY_A);
  });

  it('rejects two different keys that happen to share a key id', () => {
    // Find a second key whose one-byte id collides with KEY_A's.
    const idA = totpKeyId(Buffer.from(KEY_A, 'base64'));
    let other: Buffer;
    do other = randomBytes(32);
    while (totpKeyId(other) !== idA);
    expect(() => parseTotpKeyring(`${KEY_A},${other.toString('base64')}`)).toThrow(
      /same key id as an earlier key/,
    );
  });
});

describe('loadConfig', () => {
  it('requires TOTP_ENCRYPTION_KEY', () => {
    expect(() => loadConfig({})).toThrow(/TOTP_ENCRYPTION_KEY is not set/);
    expect(() => loadConfig({ TOTP_ENCRYPTION_KEY: 'short' })).toThrow(/32 bytes/);
  });

  it('parses a valid TOTP_ENCRYPTION_KEY', () => {
    const config = loadConfig({
      TOTP_ENCRYPTION_KEY: `${KEY_A},${KEY_B}`,
      WEBAUTHN_RP_ID: 'localhost',
      WEBAUTHN_ORIGINS: 'http://localhost:5173',
    });
    expect(config.totpKeys.byId.size).toBe(2);
  });
});

describe('TOTP secret encryption', () => {
  const keyring = parseTotpKeyring(`${KEY_A},${KEY_B}`);
  const userId = randomUUID();

  it('round-trips, in the documented 49-byte layout', () => {
    const stored = encryptTotpSecret(keyring, userId, 'active', SECRET);
    expect(stored).toHaveLength(ENCRYPTED_TOTP_SECRET_BYTES);
    expect(stored[0]).toBe(keyring.primary.id);
    expect(stored.includes(SECRET)).toBe(false);
    expect(decryptTotpSecret(keyring, userId, 'active', stored)).toEqual(SECRET);
    expect(isCurrentTotpCiphertext(keyring, stored)).toBe(true);
  });

  it('uses a fresh nonce every time', () => {
    const a = encryptTotpSecret(keyring, userId, 'active', SECRET);
    const b = encryptTotpSecret(keyring, userId, 'active', SECRET);
    expect(a.subarray(1, 13)).not.toEqual(b.subarray(1, 13));
    expect(a).not.toEqual(b);
  });

  it('is bound to the user: another account’s row cannot be copied in', () => {
    const stored = encryptTotpSecret(keyring, userId, 'active', SECRET);
    expect(() => decryptTotpSecret(keyring, randomUUID(), 'active', stored)).toThrow(
      TotpSecretDecryptionError,
    );
  });

  it('is bound to the column: a pending secret cannot be promoted to active', () => {
    const pending = encryptTotpSecret(keyring, userId, 'pending', SECRET);
    expect(() => decryptTotpSecret(keyring, userId, 'active', pending)).toThrow(
      TotpSecretDecryptionError,
    );
    expect(decryptTotpSecret(keyring, userId, 'pending', pending)).toEqual(SECRET);
  });

  it('detects tampering with any byte', () => {
    const stored = encryptTotpSecret(keyring, userId, 'active', SECRET);
    for (let i = 0; i < stored.length; i++) {
      const tampered = Buffer.from(stored);
      tampered[i]! ^= 0x01;
      expect(() => decryptTotpSecret(keyring, userId, 'active', tampered), `byte ${i}`).toThrow(
        TotpSecretDecryptionError,
      );
    }
  });

  it('decrypts with an older key after rotation, and refuses a key it no longer has', () => {
    const oldKeyring = parseTotpKeyring(KEY_B);
    const stored = encryptTotpSecret(oldKeyring, userId, 'active', SECRET);
    expect(isCurrentTotpCiphertext(keyring, stored)).toBe(false);
    expect(decryptTotpSecret(keyring, userId, 'active', stored)).toEqual(SECRET);
    expect(() => decryptTotpSecret(parseTotpKeyring(KEY_A), userId, 'active', stored)).toThrow(
      /not in TOTP_ENCRYPTION_KEY/,
    );
  });

  it('reads a legacy 20-byte plaintext secret (from before migration 005) as a copy', () => {
    const legacy = Buffer.from(SECRET);
    const read = decryptTotpSecret(keyring, userId, 'active', legacy);
    expect(read).toEqual(SECRET);
    read.fill(0);
    expect(legacy).toEqual(SECRET);
    expect(isCurrentTotpCiphertext(keyring, legacy)).toBe(false);
  });

  it('rejects stored values of any other length', () => {
    for (const length of [0, 19, 21, 48, 50]) {
      expect(() => decryptTotpSecret(keyring, userId, 'active', Buffer.alloc(length, 1))).toThrow(
        /unexpected length/,
      );
    }
  });

  it('refuses to encrypt a secret of the wrong size', () => {
    expect(() => encryptTotpSecret(keyring, userId, 'active', Buffer.alloc(16))).toThrow(
      /20 bytes/,
    );
  });
});
