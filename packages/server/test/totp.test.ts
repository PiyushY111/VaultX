import { describe, expect, it } from 'vitest';
import {
  base32Encode,
  generateRecoveryCodes,
  hashRecoveryCode,
  hotp,
  otpauthUri,
  verifyTotp,
} from '../src/totp.js';

// RFC 6238 appendix B (SHA-1 secret "12345678901234567890"), truncated to the
// last 6 of the 8 digits the RFC lists, which is what 6-digit TOTP shows.
const SECRET = Buffer.from('12345678901234567890');
const VECTORS: [number, string][] = [
  [59, '287082'],
  [1111111109, '081804'],
  [1111111111, '050471'],
  [1234567890, '005924'],
  [2000000000, '279037'],
];

describe('TOTP', () => {
  it.each(VECTORS)('matches RFC 6238 at T=%i', (seconds, code) => {
    expect(hotp(SECRET, Math.floor(seconds / 30))).toBe(code);
    expect(verifyTotp(SECRET, code, 0, seconds * 1000)).toBe(Math.floor(seconds / 30));
  });

  it('accepts one step of clock drift either way, and no more', () => {
    const now = 1_234_567_890_000;
    const step = Math.floor(now / 30_000);
    for (const offset of [-1, 0, 1]) {
      expect(verifyTotp(SECRET, hotp(SECRET, step + offset), 0, now)).toBe(step + offset);
    }
    for (const offset of [-2, 2]) {
      expect(verifyTotp(SECRET, hotp(SECRET, step + offset), 0, now)).toBeNull();
    }
  });

  it('refuses a code from a step already used', () => {
    const now = 1_234_567_890_000;
    const step = Math.floor(now / 30_000);
    expect(verifyTotp(SECRET, hotp(SECRET, step), step, now)).toBeNull();
    expect(verifyTotp(SECRET, hotp(SECRET, step), step - 1, now)).toBe(step);
  });

  it('refuses malformed codes', () => {
    for (const code of ['', '12345', '1234567', 'abcdef', '12 345']) {
      expect(verifyTotp(SECRET, code, 0)).toBeNull();
    }
  });

  it('encodes the secret as base32 in an otpauth URI', () => {
    expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI'); // RFC 4648 test vector
    const uri = new URL(otpauthUri('alice@example.com', SECRET));
    expect(uri.protocol).toBe('otpauth:');
    expect(uri.host).toBe('totp');
    expect(decodeURIComponent(uri.pathname)).toBe('/VaultX:alice@example.com');
    expect(uri.searchParams.get('secret')).toBe(base32Encode(SECRET));
    expect(uri.searchParams.get('issuer')).toBe('VaultX');
  });
});

describe('recovery codes', () => {
  it('are ten distinct XXXXX-XXXXX codes without look-alike characters', () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) expect(code).toMatch(/^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/);
  });

  it('hash the same however they are typed back in', () => {
    const [code] = generateRecoveryCodes();
    const hash = hashRecoveryCode(code!);
    expect(hashRecoveryCode(code!.toLowerCase().replace('-', ' '))).toEqual(hash);
    expect(hashRecoveryCode(code!.replace('-', ''))).toEqual(hash);
  });
});
