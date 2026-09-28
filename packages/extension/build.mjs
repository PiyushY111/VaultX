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
    offscreen: 'src/offscreen/index.ts',
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
  copyFile('src/offscreen/offscreen.html', `${outdir}/offscreen.html`),
  cp('src/popup/fonts', `${outdir}/fonts`, { recursive: true }),
  cp('icons', `${outdir}/icons`, { recursive: true }),
]);

// The content script runs inside every web page, and the offscreen document
// only touches the clipboard; neither may bundle the crypto library (and
// with it, any ability to decrypt).
for (const file of ['content.js', 'offscreen.js']) {
  const code = await readFile(`${outdir}/${file}`, 'utf8');
  const { size } = await stat(`${outdir}/${file}`);
  if (/libsodium|crypto_aead|crypto_pwhash/.test(code) || size > 50_000) {
    throw new Error(`${file} must not include crypto code (size ${size} bytes)`);
  }
}
