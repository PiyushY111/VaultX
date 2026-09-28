import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import type { Plugin } from 'vite';
import { SUMS_FILE, MANIFEST_FILE, buildHashOf, sumsText } from './sums';

/**
 * After a production build:
 *
 * 1. Adds Subresource Integrity (sha384) to every <script src> and every
 *    stylesheet / modulepreload / preload <link> in index.html, so the
 *    browser refuses an entry script or stylesheet that doesn't match the
 *    index.html it came with. (Icon links are left alone: browsers don't
 *    apply integrity to them, and an icon can't run code.)
 * 2. Writes SHA256SUMS: the SHA-256 of every file in the build, in the
 *    format `sha256sum -c` reads.
 * 3. Writes build-manifest.json: the same hashes, the build hash (SHA-256
 *    of SHA256SUMS), the SRI values, the exact package versions the build
 *    used, and the git commit it was built from, if known.
 *
 * Neither file is listed in SHA256SUMS: SHA256SUMS can't contain its own
 * hash, and the manifest holds details (commit, Node version) that differ
 * between otherwise identical builds.
 *
 * What SRI does and doesn't do here: it binds index.html to its entry
 * script and stylesheet. Chunks loaded later with import() and the KDF
 * worker are not covered by SRI (browsers have no way to attach integrity
 * to them without an inline import map, which the CSP forbids); they are in
 * SHA256SUMS. And whoever serves index.html can change the integrity values
 * along with the files, so none of this stops the server itself.
 */

const SRI_ALGORITHM = 'sha384';

export interface BuildManifest {
  format: 1;
  /** SHA-256 of SHA256SUMS: one value identifying the whole build. */
  build_hash: string;
  /** Every file in the build (paths relative to dist/, "/" separators) → SHA-256 hex. */
  files: Record<string, string>;
  /** The SRI value index.html carries for each file it references. */
  integrity: Record<string, string>;
  /** Exact versions from package-lock.json of what went into the bundle. */
  packages: Record<string, string>;
  node: string;
  git: { commit: string | null; dirty: boolean | null };
}

const sha256Hex = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const sri = (bytes: Buffer): string =>
  `${SRI_ALGORITHM}-${createHash(SRI_ALGORITHM).update(bytes).digest('base64')}`;

async function listFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => relative(dir, join(entry.parentPath, entry.name)).split(sep).join('/'))
    .filter((path) => path !== SUMS_FILE && path !== MANIFEST_FILE)
    .sort();
}

const TAG = /<(script|link)\b[^>]*>/gi;
const ATTRIBUTE = (name: string) => new RegExp(`\\s${name}="([^"]*)"`, 'i');

/** Adds integrity="…" to each script/stylesheet/preload tag; returns the new HTML and what it added. */
export async function addIntegrity(
  html: string,
  readAsset: (path: string) => Promise<Buffer>,
): Promise<{ html: string; integrity: Record<string, string> }> {
  const integrity: Record<string, string> = {};
  const replacements: [string, string][] = [];
  for (const [tag, kind] of html.matchAll(TAG)) {
    const isScript = kind!.toLowerCase() === 'script';
    const rel = ATTRIBUTE('rel').exec(tag)?.[1]?.toLowerCase();
    if (!isScript && !['stylesheet', 'modulepreload', 'preload'].includes(rel ?? '')) continue;
    const url = ATTRIBUTE(isScript ? 'src' : 'href').exec(tag)?.[1];
    if (!url) {
      if (isScript) throw new Error('index.html has an inline <script>; the CSP forbids those.');
      continue;
    }
    if (!url.startsWith('/') || url.startsWith('//')) {
      throw new Error(`index.html references ${url}; everything must come from this origin.`);
    }
    if (ATTRIBUTE('integrity').test(tag))
      throw new Error(`${url} already has an integrity attribute.`);
    const path = url.slice(1);
    const value = sri(await readAsset(path));
    integrity[path] = value;
    replacements.push([tag, tag.replace(/\s*\/?>$/, ` integrity="${value}">`)]);
  }
  let result = html;
  for (const [from, to] of replacements) result = result.replace(from, to);
  return { html: result, integrity };
}

/** Exact versions from the lockfile (read-only), for everything that ends up in the bundle. */
async function lockedVersions(
  repoRoot: string,
  packageDir: string,
): Promise<Record<string, string>> {
  const lock = JSON.parse(await readFile(join(repoRoot, 'package-lock.json'), 'utf8')) as {
    packages: Record<string, { version?: string }>;
  };
  const pkg = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8')) as {
    name: string;
    version: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const cryptoPkg = JSON.parse(
    await readFile(join(repoRoot, 'packages/crypto/package.json'), 'utf8'),
  ) as { dependencies?: Record<string, string> };
  const names = [
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
    ...Object.keys(cryptoPkg.dependencies ?? {}),
    'libsodium-sumo',
    'typescript',
    'rolldown',
  ];
  const versions: Record<string, string> = { [pkg.name]: pkg.version };
  for (const name of [...new Set(names)].sort()) {
    const entry =
      lock.packages[`packages/web/node_modules/${name}`] ?? lock.packages[`node_modules/${name}`];
    if (entry?.version) versions[name] = entry.version;
  }
  return versions;
}

/** The commit the build came from, via read-only git commands; null when there's no repository. */
function gitInfo(repoRoot: string): BuildManifest['git'] {
  // --no-optional-locks: `git status` then doesn't refresh (write) the index.
  const git = (...args: string[]) =>
    execFileSync('git', ['--no-optional-locks', ...args], {
      cwd: repoRoot,
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    }).trim();
  try {
    return { commit: git('rev-parse', 'HEAD'), dirty: git('status', '--porcelain') !== '' };
  } catch {
    return { commit: null, dirty: null };
  }
}

export function buildIntegrity({ repoRoot }: { repoRoot: string }): Plugin {
  let outDir = '';
  let packageDir = '';
  return {
    name: 'vaultx-build-integrity',
    apply: 'build',
    enforce: 'post',
    configResolved(config) {
      packageDir = config.root;
      outDir = resolve(config.root, config.build.outDir);
    },
    async closeBundle() {
      const htmlPath = join(outDir, 'index.html');
      const { html, integrity } = await addIntegrity(await readFile(htmlPath, 'utf8'), (path) =>
        readFile(join(outDir, path)),
      );
      await writeFile(htmlPath, html);

      const files: Record<string, string> = {};
      for (const path of await listFiles(outDir)) {
        files[path] = sha256Hex(await readFile(join(outDir, path)));
      }
      const sums = sumsText(files);
      await writeFile(join(outDir, SUMS_FILE), sums);

      const manifest: BuildManifest = {
        format: 1,
        build_hash: await buildHashOf(sums),
        files,
        integrity,
        packages: await lockedVersions(repoRoot, packageDir),
        node: process.version,
        git: gitInfo(repoRoot),
      };
      await writeFile(join(outDir, MANIFEST_FILE), `${JSON.stringify(manifest, null, 2)}\n`);
    },
  };
}
