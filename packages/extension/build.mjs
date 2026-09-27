// Bundles the extension into dist/ (load that folder as an unpacked extension).
// Each entry is a single IIFE: MV3 content scripts can't be ES modules.
import { build } from 'esbuild';
import { copyFile, cp, mkdir, readFile, rm, stat } from 'node:fs/promises';

const outdir = 'dist';
await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

await build({
  entryPoints: {
    background: 'src/background/index.ts',
    content: 'src/content/index.ts',
    popup: 'src/popup/index.ts',
  },
  outdir,
  bundle: true,
  format: 'iife',
  target: 'chrome120',
  minify: true,
  legalComments: 'none',
  logLevel: 'info',
});

await Promise.all([
  copyFile('manifest.json', `${outdir}/manifest.json`),
  copyFile('src/popup/popup.html', `${outdir}/popup.html`),
  copyFile('src/popup/popup.css', `${outdir}/popup.css`),
  cp('src/popup/fonts', `${outdir}/fonts`, { recursive: true }),
]);

// The content script runs inside every web page; it must never bundle the
// crypto library (and with it, any ability to decrypt).
const content = await readFile(`${outdir}/content.js`, 'utf8');
const { size } = await stat(`${outdir}/content.js`);
if (/libsodium|crypto_aead|crypto_pwhash/.test(content) || size > 50_000) {
  throw new Error(`content.js must not include crypto code (size ${size} bytes)`);
}
