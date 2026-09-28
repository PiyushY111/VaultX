import { describe, expect, it } from 'vitest';
import { CryptoInputError, parseTotp, totpCode, type TotpConfig } from '../src/index.js';

const ascii = (text: string) => new TextEncoder().encode(text);

// RFC 6238 appendix B: 8-digit codes for each hash, with its test key.
const KEYS = {
  'SHA-1': ascii('12345678901234567890'),
  'SHA-256': ascii('12345678901234567890123456789012'),
  'SHA-512': ascii('1234567890123456789012345678901234567890123456789012345678901234'),
} as const;
const VECTORS: [number, string, string, string][] = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1234567890, '89005924', '91819424', '93441116'],
  [20000000000, '65353130', '77737706', '47863826'],
];

describe('totpCode', () => {
  it.each(VECTORS)('matches RFC 6238 at T=%i', async (seconds, sha1, sha256, sha512) => {
    for (const [algorithm, expected] of [
      ['SHA-1', sha1],
      ['SHA-256', sha256],
      ['SHA-512', sha512],
    ] as const) {
      const config: TotpConfig = { secret: KEYS[algorithm], algorithm, digits: 8, period: 30 };
      expect((await totpCode(config, seconds * 1000)).code).toBe(expected);
    }
  });

  it('reports the seconds left on the current code', async () => {
    const config = { secret: KEYS['SHA-1'], algorithm: 'SHA-1', digits: 6, period: 30 } as const;
    expect(await totpCode(config, 59_000)).toEqual({ code: '287082', secondsLeft: 1 });
    expect((await totpCode(config, 60_000)).secondsLeft).toBe(30);
  });
});

describe('parseTotp', () => {
  // "12345678901234567890" in base32.
  const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  it('reads a bare setup key, spaces and case ignored', () => {
    const config = parseTotp('gezd gnbv gy3t qojq gezd gnbv gy3t qojq');
    expect(config).toEqual({ secret: KEYS['SHA-1'], algorithm: 'SHA-1', digits: 6, period: 30 });
  });

  it('reads an otpauth:// link with its settings, issuer and account', () => {
    expect(
      parseTotp(
        `otpauth://totp/GitHub:octocat%40example.com?secret=${SECRET}&issuer=GitHub&algorithm=SHA256&digits=8&period=60`,
      ),
    ).toEqual({
      secret: KEYS['SHA-1'],
      algorithm: 'SHA-256',
      digits: 8,
      period: 60,
      issuer: 'GitHub',
      account: 'octocat@example.com',
    });
    expect(parseTotp(`otpauth://totp/alice?secret=${SECRET}`)).toMatchObject({
      account: 'alice',
      algorithm: 'SHA-1',
    });
  });

  it.each([
    ['not base32', 'hello world!'],
    ['too short', 'ABCDEF'],
    ['counter-based', `otpauth://hotp/x?secret=${SECRET}&counter=1`],
    ['bad digits', `otpauth://totp/x?secret=${SECRET}&digits=10`],
    ['bad algorithm', `otpauth://totp/x?secret=${SECRET}&algorithm=MD5`],
    ['no secret', 'otpauth://totp/x?issuer=Y'],
  ])('refuses %s', (_, input) => {
    expect(() => parseTotp(input)).toThrow(CryptoInputError);
  });
});
