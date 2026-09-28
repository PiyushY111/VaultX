import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv, type Plugin, type ProxyOptions } from 'vite';
import { CONTENT_SECURITY_POLICY } from './build/csp';
import { buildIntegrity } from './build/integrity-plugin';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

// Output names depend only on file contents (no timestamps, no build paths),
// so the same source and lockfile give byte-identical output; see
// `npm run verify-build`. Spelled out so a Vite default can't change them.
const OUTPUT_NAMES = {
  entryFileNames: 'assets/[name]-[hash].js',
  chunkFileNames: 'assets/[name]-[hash].js',
  assetFileNames: 'assets/[name]-[hash][extname]',
};

// Applied to production builds only: the dev server needs inline scripts for
// hot reloading. The policy itself is in build/csp.ts.
function contentSecurityPolicy(): Plugin {
  return {
    name: 'content-security-policy',
    apply: 'build',
    transformIndexHtml: (html) =>
      html.replace(
        '<meta charset="UTF-8" />',
        `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CONTENT_SECURITY_POLICY}" />`,
      ),
  };
}

export default defineConfig(({ mode }) => {
  // The app calls same-origin /api/*; the dev and preview servers forward it
  // to the API, so no CORS is needed. In production, serve the app and API
  // behind one reverse proxy the same way.
  const apiUrl = loadEnv(mode, process.cwd(), '').API_URL || 'http://127.0.0.1:3000';
  const proxy: Record<string, ProxyOptions> = {
    '/api': { target: apiUrl, changeOrigin: true, rewrite: (path) => path.replace(/^\/api/, '') },
  };
  return {
    plugins: [react(), contentSecurityPolicy(), buildIntegrity({ repoRoot: REPO_ROOT })],
    server: { proxy },
    preview: { proxy },
    // libsodium's sumo build (Argon2id) embeds ~700 kB of WebAssembly, and
    // zxcvbn's English dictionary is ~1.2 MB; it's loaded only when a
    // strength meter first appears.
    build: {
      chunkSizeWarningLimit: 1300,
      rolldownOptions: { output: OUTPUT_NAMES },
    },
    // The KDF worker (src/vault/kdf.worker.ts) is a module worker.
    worker: { format: 'es', rolldownOptions: { output: OUTPUT_NAMES } },
  };
});
