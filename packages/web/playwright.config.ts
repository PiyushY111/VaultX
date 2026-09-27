import { defineConfig } from '@playwright/test';

// Runs the production build (with its CSP) against a real API server, e.g.
// the one from `docker compose up`. Uses the locally installed Chrome.
const API_URL = process.env.API_URL ?? 'http://127.0.0.1:3000';
const PORT = 4173;

export default defineConfig({
  testDir: 'e2e',
  timeout: 60_000,
  workers: 1,
  use: { baseURL: `http://127.0.0.1:${PORT}`, channel: 'chrome', headless: true },
  webServer: {
    command: `npm run build && npx vite preview --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    env: { API_URL },
    timeout: 120_000,
  },
});
