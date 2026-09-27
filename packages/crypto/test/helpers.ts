import sodium from 'libsodium-wrappers-sumo';
import { vi } from 'vitest';

export const fromHex = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));
export const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Bytes `start, start+1, ...` — handy for readable fixed test inputs. */
export const sequence = (length: number, start = 0): Uint8Array =>
  Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);

/**
 * Makes the next libsodium `randombytes_buf` call return `bytes`, so an
 * encryption produces a deterministic, known-answer ciphertext. Test-only:
 * the public API never accepts a caller-chosen nonce.
 */
export async function fixNextRandomBytes(bytes: Uint8Array): Promise<void> {
  await sodium.ready;
  // Cast: vi.spyOn picks the string-returning overload of randombytes_buf.
  const spy = vi.spyOn(sodium, 'randombytes_buf') as unknown as {
    mockImplementationOnce(fn: () => Uint8Array): void;
  };
  spy.mockImplementationOnce(() => Uint8Array.from(bytes));
}

export { sodium };
