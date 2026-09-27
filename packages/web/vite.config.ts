import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, type Plugin, type ProxyOptions } from 'vite';

// Applied to production builds only: the dev server needs inline scripts for
// hot reloading. 'wasm-unsafe-eval' lets libsodium compile its WebAssembly;
// everything else is locked to this origin.
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

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
    plugins: [react(), contentSecurityPolicy()],
    server: { proxy },
    preview: { proxy },
    // libsodium's sumo build (Argon2id) embeds ~700 kB of WebAssembly.
    build: { chunkSizeWarningLimit: 1024 },
  };
});
