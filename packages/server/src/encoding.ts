import { badRequest } from './http-errors.js';

/** Canonical, padded standard base64. */
export const BASE64_PATTERN = '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$';

/** Max base64 string length that encodes `bytes` bytes. */
export const base64Length = (bytes: number): number => 4 * Math.ceil(bytes / 3);

export function base64Schema(maxBytes: number) {
  return { type: 'string', pattern: BASE64_PATTERN, maxLength: base64Length(maxBytes) } as const;
}

type LengthRule = { exact: number } | { min: number; max: number };

/**
 * Decodes a base64 field (already format-checked by the route schema) and
 * enforces its byte length, throwing a 400 on mismatch.
 */
export function decodeBytes(value: string, field: string, rule: LengthRule): Buffer {
  const bytes = Buffer.from(value, 'base64');
  if ('exact' in rule) {
    if (bytes.length !== rule.exact) {
      throw badRequest(`${field} must decode to exactly ${rule.exact} bytes`);
    }
  } else if (bytes.length < rule.min || bytes.length > rule.max) {
    throw badRequest(`${field} must decode to between ${rule.min} and ${rule.max} bytes`);
  }
  return bytes;
}

export const encodeBytes = (bytes: Buffer): string => bytes.toString('base64');
