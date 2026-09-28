// @vitest-environment node
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY } from '../build/csp';
import type { BuildManifest } from '../build/integrity-plugin';
import { buildHashOf, sumsText } from '../build/sums';

/**
 * Builds the production bundle (twice, into temporary directories) and
 * checks what ships: the exact CSP, no inline script anywhere, SRI on every
 * script and stylesheet, SHA256SUMS and the manifest, and that two builds
 * of the same source are byte-identical.
 */

const WEB_DIR = fileURLToPath(new URL('..', import.meta.url));
const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

// Spelled out, so any change to the policy has to change this test too.
const EXPECTED_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
  "connect-src 'self' https://api.pwnedpasswords.com; img-src 'self' data:; " +
  "object-src 'none'; base-uri 'none'; form-action 'none'; " +
  "require-trusted-types-for 'script'; trusted-types vaultx-kdf-worker";

async function buildInto(): Promise<string> {
  const outDir = await mkdtemp(join(tmpdir(), 'vaultx-web-build-'));
  // Vitest sets NODE_ENV=test, which would make Vite bundle React's
  // development build; build exactly what `npm run build` ships.
  const nodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    await build({
      root: WEB_DIR,
      configFile: join(WEB_DIR, 'vite.config.ts'),
      mode: 'production',
      logLevel: 'silent',
      build: { outDir, emptyOutDir: true },
    });
  } finally {
    process.env.NODE_ENV = nodeEnv;
  }
  return outDir;
}

async function filesIn(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => relative(dir, join(entry.parentPath, entry.name)).split(sep).join('/'))
    .sort();
}

let first: string;
let second: string;
let html: string;
let manifest: BuildManifest;

beforeAll(async () => {
  first = await buildInto();
  second = await buildInto();
  html = await readFile(join(first, 'index.html'), 'utf8');
  manifest = JSON.parse(await readFile(join(first, 'build-manifest.json'), 'utf8'));
}, 120_000);

afterAll(async () => {
  for (const dir of [first, second]) if (dir) await rm(dir, { recursive: true, force: true });
});

describe('production build', () => {
  it('ships exactly the expected CSP, as the first thing in <head>', () => {
    expect(CONTENT_SECURITY_POLICY).toBe(EXPECTED_CSP);
    const metas = [
      ...html.matchAll(/<meta http-equiv="Content-Security-Policy" content="([^"]*)"/g),
    ];
    expect(metas.map((m) => m[1])).toEqual([EXPECTED_CSP]);
    expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<script'));
  });

  it('has no inline scripts, event handlers, javascript: URLs or inline styles', () => {
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts.length).toBeGreaterThan(0);
    for (const [, attributes, body] of scripts) {
      expect(attributes).toMatch(/\ssrc="\/assets\/[^"]+\.js"/);
      expect(body!.trim()).toBe('');
    }
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/javascript:/i);
    expect(html).not.toMatch(/<style\b/i);
    expect(html).not.toMatch(/\sstyle\s*=/i);
    expect(html).not.toMatch(/type="importmap"/i);
  });

  it('puts SRI on every script and stylesheet, matching the files', async () => {
    const tags = [
      ...html.matchAll(/<script\b[^>]*\bsrc="\/([^"]+)"[^>]*>/g),
      ...html.matchAll(
        /<link\b[^>]*\brel="(?:stylesheet|modulepreload)"[^>]*\bhref="\/([^"]+)"[^>]*>/g,
      ),
    ];
    expect(tags.length).toBeGreaterThanOrEqual(2);
    for (const [tag, path] of tags) {
      const bytes = await readFile(join(first, path!));
      const expected = `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
      expect(tag).toContain(`integrity="${expected}"`);
      expect(manifest.integrity[path!]).toBe(expected);
    }
  });

  it('writes SHA256SUMS covering every file, and a manifest whose build hash is its SHA-256', async () => {
    const sums = await readFile(join(first, 'SHA256SUMS'), 'utf8');
    const listed = sums
      .trimEnd()
      .split('\n')
      .map((line) => line.split('  '));
    const files = (await filesIn(first)).filter(
      (path) => path !== 'SHA256SUMS' && path !== 'build-manifest.json',
    );
    expect(listed.map(([, path]) => path)).toEqual(files);
    for (const [hash, path] of listed) {
      const bytes = await readFile(join(first, path!));
      expect(hash).toBe(createHash('sha256').update(bytes).digest('hex'));
    }
    expect(sumsText(manifest.files)).toBe(sums);
    expect(manifest.build_hash).toBe(createHash('sha256').update(sums).digest('hex'));
    expect(await buildHashOf(sums)).toBe(manifest.build_hash);
    expect(manifest.packages).toMatchObject({
      react: expect.stringMatching(/^\d+\.\d+\.\d+$/),
      vite: expect.stringMatching(/^\d+\.\d+\.\d+$/),
      'libsodium-wrappers-sumo': expect.stringMatching(/^\d+\.\d+\.\d+$/),
    });
  });

  it('is reproducible: two builds are byte-identical, with no paths or timestamps in them', async () => {
    const [a, b] = await Promise.all([
      readFile(join(first, 'SHA256SUMS'), 'utf8'),
      readFile(join(second, 'SHA256SUMS'), 'utf8'),
    ]);
    expect(b).toBe(a);
    for (const path of Object.keys(manifest.files)) {
      if (!/\.(js|css|html)$/.test(path)) continue;
      const text = await readFile(join(first, path), 'utf8');
      expect(text, path).not.toContain(REPO_ROOT);
      expect(text, path).not.toContain(first);
      expect(text, path).not.toMatch(/\b20\d\d-\d\d-\d\dT\d\d:\d\d/);
      // A production bundle: no development-only React code (which embeds source paths).
      expect(text, path).not.toContain('is deprecated in plain JavaScript React classes');
    }
  });
});
