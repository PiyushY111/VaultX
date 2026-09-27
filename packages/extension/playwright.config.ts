import { defineConfig } from '@playwright/test';

// Loads dist/ as an unpacked extension in Playwright's Chromium (branded
// Chrome no longer supports --load-extension). Needs the API running, e.g.
// `docker compose up`, reachable at API_URL.
export default defineConfig({
  testDir: 'e2e',
  timeout: 90_000,
  workers: 1,
});
