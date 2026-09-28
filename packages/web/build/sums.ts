/**
 * The SHA256SUMS format and the build hash, shared by the build plugin (Node)
 * and the Security panel (browser), so both compute the same value. Uses
 * only Web Crypto, which both have.
 */

export const SUMS_FILE = 'SHA256SUMS';
export const MANIFEST_FILE = 'build-manifest.json';

/** `sha256sum` output: "<hex>  <path>" per line, sorted by path, trailing newline. */
export function sumsText(files: Record<string, string>): string {
  return Object.keys(files)
    .sort()
    .map((path) => `${files[path]}  ${path}\n`)
    .join('');
}

/** SHA-256 of the SHA256SUMS text, as hex: one value that identifies the whole build. */
export async function buildHashOf(sums: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(sums));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
