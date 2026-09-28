import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadBuildInfo } from './buildInfo';

const FILES = {
  'index.html': 'a'.repeat(64),
  'assets/index-abc.js': 'b'.repeat(64),
  'assets/index-def.css': 'c'.repeat(64),
};
const SUMS = Object.keys(FILES)
  .sort()
  .map((path) => `${FILES[path as keyof typeof FILES]}  ${path}\n`)
  .join('');
const BUILD_HASH = createHash('sha256').update(SUMS).digest('hex');
const INTEGRITY = {
  'assets/index-abc.js': 'sha384-script',
  'assets/index-def.css': 'sha384-style',
};

function page(scriptIntegrity: string | null = 'sha384-script'): Document {
  const doc = document.implementation.createHTMLDocument('VaultX');
  const base = doc.createElement('base');
  base.href = 'https://vault.test/';
  doc.head.append(base);
  const script = doc.createElement('script');
  script.type = 'module';
  script.setAttribute('src', '/assets/index-abc.js');
  if (scriptIntegrity) script.setAttribute('integrity', scriptIntegrity);
  const style = doc.createElement('link');
  style.rel = 'stylesheet';
  style.setAttribute('href', '/assets/index-def.css');
  style.setAttribute('integrity', 'sha384-style');
  doc.head.append(script, style);
  return doc;
}

function serve(manifest: unknown, status = 200) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(manifest), { status })),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const manifest = (overrides: Record<string, unknown> = {}) => ({
  format: 1,
  build_hash: BUILD_HASH,
  files: FILES,
  integrity: INTEGRITY,
  git: { commit: 'f'.repeat(40), dirty: false },
  ...overrides,
});

describe('loadBuildInfo', () => {
  it('recomputes the build hash as SHA-256 of SHA256SUMS, the value `sha256sum SHA256SUMS` prints', async () => {
    serve(manifest());
    expect(await loadBuildInfo(page())).toEqual({
      buildHash: BUILD_HASH,
      commit: 'f'.repeat(40),
      dirty: false,
      problems: [],
    });
    expect(fetch).toHaveBeenCalledWith('/build-manifest.json', {
      cache: 'no-store',
      credentials: 'omit',
    });
  });

  it('reports a manifest whose file list doesn’t match its build hash', async () => {
    serve(manifest({ files: { ...FILES, 'index.html': 'd'.repeat(64) } }));
    const info = await loadBuildInfo(page());
    expect(info!.buildHash).not.toBe(BUILD_HASH);
    expect(info!.problems).toEqual([
      'The build manifest’s file list doesn’t match its own build hash.',
    ]);
  });

  it('reports a loaded script that isn’t the one in the manifest, or has no integrity', async () => {
    serve(manifest());
    expect((await loadBuildInfo(page('sha384-other')))!.problems).toEqual([
      'assets/index-abc.js on this page isn’t the file the build manifest lists.',
    ]);
    serve(manifest());
    expect((await loadBuildInfo(page(null)))!.problems).toEqual([
      'assets/index-abc.js was loaded without an integrity check.',
    ]);
  });

  it('reports a loaded script that isn’t part of the build at all', async () => {
    serve(manifest());
    const doc = page();
    const extra = doc.createElement('script');
    extra.setAttribute('src', '/assets/injected.js');
    doc.head.append(extra);
    expect((await loadBuildInfo(doc))!.problems).toEqual([
      'This page loaded assets/injected.js, which isn’t in the build.',
    ]);
  });

  it('returns null without a usable manifest (e.g. the dev server)', async () => {
    serve({}, 404);
    expect(await loadBuildInfo(page())).toBeNull();
    serve({ build_hash: 1 });
    expect(await loadBuildInfo(page())).toBeNull();
    serve(manifest({ files: { 'index.html': 'not-a-hash' } }));
    expect(await loadBuildInfo(page())).toBeNull();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Promise.reject(new TypeError('offline'))),
    );
    expect(await loadBuildInfo(page())).toBeNull();
  });
});
