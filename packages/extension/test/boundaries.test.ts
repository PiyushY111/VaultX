import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));

async function sources(dir: string): Promise<string[]> {
  const entries = await readdir(join(root, dir), { withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && e.name.endsWith('.ts'))
    .map((e) => join(root, dir, e.name));
}

describe('code boundaries', () => {
  it.each(['src/content', 'src/popup', 'src/shared'])(
    '%s never imports the crypto package or background code',
    async (dir) => {
      for (const file of await sources(dir)) {
        const source = await readFile(file, 'utf8');
        expect(source, file).not.toMatch(
          /from ['"](@password-manager\/crypto|libsodium|\.\.\/background)/,
        );
      }
    },
  );

  it('nothing uses localStorage, sessionStorage or IndexedDB', async () => {
    for (const dir of ['src/background', 'src/content', 'src/popup', 'src/shared']) {
      for (const file of await sources(dir)) {
        expect(await readFile(file, 'utf8'), file).not.toMatch(
          /\b(localStorage|sessionStorage|indexedDB)\s*[.[]/,
        );
      }
    }
  });

  it('item data is never rendered with innerHTML', async () => {
    for (const dir of ['src/content', 'src/popup']) {
      for (const file of await sources(dir)) {
        expect(await readFile(file, 'utf8'), file).not.toMatch(
          /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML/,
        );
      }
    }
  });
});

describe('manifest', async () => {
  const manifest = JSON.parse(await readFile(join(root, 'manifest.json'), 'utf8'));

  it('is Manifest V3', () => {
    expect(manifest.manifest_version).toBe(3);
  });

  it('does not let web pages message the extension', () => {
    expect(manifest.externally_connectable).toBeUndefined();
  });

  it('runs the content script in top frames only, on https (and localhost) only', () => {
    expect(manifest.content_scripts).toHaveLength(1);
    expect(manifest.content_scripts[0].all_frames).toBe(false);
    for (const pattern of manifest.content_scripts[0].matches) {
      expect(pattern).toMatch(/^(https:\/\/\*\/\*|http:\/\/(localhost|127\.0\.0\.1)\/\*)$/);
    }
  });

  it('requests only the permissions it uses', () => {
    // offscreen + clipboardWrite: clearing a copied password (background/clipboard.ts).
    // Neither shows an install warning; clipboardRead (which would) is not requested.
    expect(manifest.permissions.sort()).toEqual([
      'alarms',
      'clipboardWrite',
      'idle',
      'offscreen',
      'storage',
    ]);
  });

  it('allows WebAssembly but never eval or remote scripts', () => {
    const csp: string = manifest.content_security_policy.extension_pages;
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).not.toMatch(/'unsafe-eval'|'unsafe-inline'|https?:/);
  });
});
