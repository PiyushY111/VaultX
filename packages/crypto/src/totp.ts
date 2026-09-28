import { CryptoInputError } from './errors.js';

/**
 * TOTP codes (RFC 6238) for the two-factor secrets stored in vault items, so
 * the vault can show a site's current code and the extension can fill it.
 *
 * Uses WebCrypto's HMAC (libsodium has no HMAC-SHA1, which nearly every site
 * uses), available in browsers, service workers and Node.
 */

export interface TotpConfig {
  secret: Uint8Array;
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512';
  digits: number;
  /** Seconds per code. */
  period: number;
  /** From an otpauth:// link, for display. */
  issuer?: string;
  account?: string;
}

// This package is built without DOM types; these are the only WebCrypto
// calls it makes (present in browsers, service workers and Node 20+).
interface HmacSubtle {
  importKey(
    format: 'raw',
    keyData: Uint8Array,
    algorithm: { name: 'HMAC'; hash: string },
    extractable: false,
    usages: ['sign'],
  ): Promise<unknown>;
  sign(algorithm: 'HMAC', key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
}
const subtle = () => (globalThis as unknown as { crypto: { subtle: HmacSubtle } }).crypto.subtle;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' } as const;

function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean || !/^[A-Z2-7]+$/.test(clean)) {
    throw new CryptoInputError(
      'That isn’t a valid setup key. It should be letters A–Z and digits 2–7, or an otpauth:// link.',
    );
  }
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    value = (value << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(bytes);
}

/**
 * Reads what a site gives you when you turn on two-factor: its setup key
 * (base32, spaces allowed) or the `otpauth://totp/…` link inside its QR code.
 * Throws {@link CryptoInputError} with a message fit to show.
 */
export function parseTotp(input: string): TotpConfig {
  const text = input.trim();
  if (!/^otpauth:/i.test(text)) {
    const secret = base32Decode(text);
    if (secret.length < 10) throw new CryptoInputError('That setup key is too short.');
    return { secret, algorithm: 'SHA-1', digits: 6, period: 30 };
  }

  const match = /^otpauth:\/\/([^/?#]+)\/?([^?#]*)(?:\?([^#]*))?/i.exec(text);
  if (!match) throw new CryptoInputError('That otpauth:// link is malformed.');
  const [, type, path = '', query = ''] = match;
  if (type!.toLowerCase() !== 'totp') {
    throw new CryptoInputError('Only time-based (TOTP) codes are supported, not counter-based.');
  }
  const decode = (value: string) => {
    try {
      return decodeURIComponent(value.replace(/\+/g, ' '));
    } catch {
      throw new CryptoInputError('That otpauth:// link is malformed.');
    }
  };
  const queryValues = new Map(
    query
      .split('&')
      .filter(Boolean)
      .map((pair) => {
        const [key = '', value = ''] = pair.split(/=(.*)/s);
        return [decode(key).toLowerCase(), decode(value)] as const;
      }),
  );
  const params = { get: (name: string) => queryValues.get(name) ?? null };
  const algorithm =
    ALGORITHMS[(params.get('algorithm') ?? 'SHA1').toUpperCase() as keyof typeof ALGORITHMS];
  const digits = Number(params.get('digits') ?? 6);
  const period = Number(params.get('period') ?? 30);
  if (!algorithm) throw new CryptoInputError('Unsupported algorithm in the otpauth:// link.');
  if (![6, 7, 8].includes(digits)) throw new CryptoInputError('Codes must have 6 to 8 digits.');
  if (!Number.isInteger(period) || period < 1 || period > 300) {
    throw new CryptoInputError('Unsupported period in the otpauth:// link.');
  }
  const secret = base32Decode(params.get('secret') ?? '');
  if (secret.length < 10) throw new CryptoInputError('That setup key is too short.');

  // The label is "Issuer:account" or just "account".
  const label = decode(path);
  const [labelIssuer, account] = label.includes(':') ? label.split(/:(.*)/s) : [undefined, label];
  const issuer = params.get('issuer') ?? labelIssuer;
  return {
    secret,
    algorithm,
    digits,
    period,
    ...(issuer && { issuer }),
    ...(account && { account: account.trim() }),
  };
}

/** The code for `nowMs`, and how many seconds it has left. */
export async function totpCode(
  config: TotpConfig,
  nowMs = Date.now(),
): Promise<{ code: string; secondsLeft: number }> {
  const seconds = Math.floor(nowMs / 1000);
  const counter = Math.floor(seconds / config.period);
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const key = await subtle().importKey(
    'raw',
    config.secret,
    { name: 'HMAC', hash: config.algorithm },
    false,
    ['sign'],
  );
  const digest = new Uint8Array(await subtle().sign('HMAC', key, message));
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    (digest[offset + 1]! << 16) |
    (digest[offset + 2]! << 8) |
    digest[offset + 3]!;
  return {
    code: String(binary % 10 ** config.digits).padStart(config.digits, '0'),
    secondsLeft: config.period - (seconds % config.period),
  };
}
