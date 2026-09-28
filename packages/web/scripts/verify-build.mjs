/* global Buffer, URL, console, fetch, process */
// Checks a web vault build against a published SHA256SUMS.
//
//   npm run verify-build -w @password-manager/web -- --sums <file or URL> [--ref <git ref>] [--keep]
//     Rebuilds from source in a clean temporary directory (fresh `npm ci`
//     from package-lock.json) and compares every file's hash.
//     Without --ref it builds this checkout's files (tracked and untracked,
//     minus .gitignore'd ones); with --ref it builds that commit or tag
//     (`git archive`, which only reads the repository).
//
//   npm run verify-build -w @password-manager/web -- --sums <file or URL> --site <https://vault.example.com>
//     Doesn't rebuild: downloads every listed file from a running server and
//     compares those. It checks what that server sent to this machine, this
//     once; a server can send other people something else.
//
// Exits 0 when everything matches, 1 on any difference.
// Never runs a git command that changes the repository.
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const WEB_PATH = 'packages/web';
const SUMS_LINE = /^([0-9a-f]{64}) {2}([^\n]+)$/;

function usage(message) {
  if (message) console.error(`verify-build: ${message}\n`);
  console.error(
    'Usage: npm run verify-build -w @password-manager/web -- --sums <file|URL> [--ref <git ref>] [--site <URL>] [--keep]',
  );
  process.exit(2);
}

function parseArgs(argv) {
  const options = { sums: null, ref: null, site: null, keep: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--keep') options.keep = true;
    else if (arg === '--sums' || arg === '--ref' || arg === '--site') {
      const value = argv[++i];
      if (!value) usage(`${arg} needs a value`);
      options[arg.slice(2)] = value;
    } else usage(`unknown argument ${arg}`);
  }
  if (!options.sums) usage('--sums is required: the SHA256SUMS published for the release');
  if (options.site && options.ref) usage('--site and --ref don’t go together');
  return options;
}

/** Only https, or http to this machine: a download over plain HTTP proves nothing. */
function checkedUrl(value) {
  const url = new URL(value);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error(`${value}: use https (http is allowed for localhost only)`);
  }
  return url;
}

async function fetchBytes(url) {
  const response = await fetch(url, { cache: 'no-store', redirect: 'error' });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

async function readSums(source) {
  const text = /^https?:\/\//.test(source)
    ? (await fetchBytes(checkedUrl(source))).toString('utf8')
    : await readFile(source, 'utf8');
  const sums = new Map();
  for (const [index, line] of text.split('\n').entries()) {
    if (line === '') continue;
    const match = SUMS_LINE.exec(line);
    const path = match?.[2];
    if (!match || path.startsWith('/') || path.split('/').includes('..')) {
      throw new Error(`${source}: line ${index + 1} isn’t "<sha256>  <relative path>"`);
    }
    sums.set(path, match[1]);
  }
  if (sums.size === 0) throw new Error(`${source}: no files listed`);
  return { text, sums };
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function run(command, args, cwd, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: 'inherit',
      env: { ...process.env, ...extraEnv },
    });
    child.on('error', reject);
    child.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`${command} ${args.join(' ')} exited ${code}`)),
    );
  });
}

// Read-only git: listing files and writing an archive to stdout.
const git = (args, options = {}) =>
  execFileSync('git', ['--no-optional-locks', ...args], { cwd: REPO_ROOT, ...options });

async function copyWorkingTree(dest) {
  let listing;
  try {
    listing = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    throw new Error('Not a git checkout. Use --ref <tag> in a clone, or run from the repository.');
  }
  for (const path of listing.split('\0').filter(Boolean)) {
    const from = join(REPO_ROOT, path);
    // Deleted but not yet committed files are still listed; skip them.
    if (!(await stat(from).catch(() => null))?.isFile()) continue;
    await mkdir(dirname(join(dest, path)), { recursive: true });
    await cp(from, join(dest, path));
  }
}

async function extractRef(ref, dest) {
  await new Promise((resolve, reject) => {
    const archive = spawn('git', ['--no-optional-locks', 'archive', '--format=tar', ref], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    const tar = spawn('tar', ['-x', '-f', '-', '-C', dest], {
      stdio: ['pipe', 'inherit', 'inherit'],
    });
    archive.stdout.pipe(tar.stdin);
    let failed = false;
    const fail = (error) => {
      if (!failed) reject(error);
      failed = true;
    };
    archive.on(
      'exit',
      (code) => code !== 0 && fail(new Error(`git archive ${ref} exited ${code}`)),
    );
    tar.on('exit', (code) =>
      code === 0 ? !failed && resolve() : fail(new Error(`tar exited ${code}`)),
    );
  });
}

/** Differences between two path → hash maps, as printable lines. */
function compare(expected, actual) {
  const problems = [];
  for (const [path, hash] of expected) {
    if (!actual.has(path)) problems.push(`missing:   ${path}`);
    else if (actual.get(path) !== hash) problems.push(`differs:   ${path}`);
  }
  for (const path of actual.keys()) {
    if (!expected.has(path)) problems.push(`unexpected: ${path}`);
  }
  return problems;
}

async function rebuild(options) {
  const dir = await mkdtemp(join(tmpdir(), 'vaultx-verify-build-'));
  console.log(`Building in ${dir}`);
  try {
    if (options.ref) await extractRef(options.ref, dir);
    else await copyWorkingTree(dir);
    await run(
      'npm',
      [
        'ci',
        '--workspace=@password-manager/web',
        '--include-workspace-root',
        '--no-audit',
        '--no-fund',
      ],
      dir,
    );
    await run('npm', ['run', 'build', '-w', '@password-manager/web'], dir, {
      NODE_ENV: 'production',
    });
    const builtSums = join(dir, WEB_PATH, 'dist', 'SHA256SUMS');
    if (!(await stat(builtSums).catch(() => null))) {
      throw new Error(
        'The rebuilt source wrote no dist/SHA256SUMS: it predates build verification, so there is nothing to compare.',
      );
    }
    return (await readSums(builtSums)).sums;
  } finally {
    if (options.keep) console.log(`Kept ${dir}`);
    else await rm(dir, { recursive: true, force: true });
  }
}

async function download(site, sums) {
  const base = checkedUrl(site);
  const actual = new Map();
  for (const path of sums.keys()) {
    const url = new URL(path, base);
    if (url.origin !== base.origin) throw new Error(`${path} points off ${base.origin}`);
    actual.set(path, sha256(await fetchBytes(url)));
  }
  return actual;
}

const options = parseArgs(process.argv.slice(2));
try {
  const published = await readSums(options.sums);
  const actual = options.site
    ? await download(options.site, published.sums)
    : await rebuild(options);
  const problems = compare(published.sums, actual);
  const buildHash = sha256(Buffer.from(published.text));
  if (problems.length) {
    console.error(`\nMISMATCH against ${options.sums}:`);
    for (const line of problems) console.error(`  ${line}`);
    process.exit(1);
  }
  console.log(
    `\nOK: all ${published.sums.size} files match ${options.sums}.\nBuild hash (SHA-256 of SHA256SUMS): ${buildHash}`,
  );
} catch (error) {
  console.error(`verify-build: ${error instanceof Error ? error.message : error}`);
  process.exit(1);
}
