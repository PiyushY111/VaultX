import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/global-setup.ts'],
    // Pulling the Postgres image on a first run can take a while.
    hookTimeout: 180_000,
    testTimeout: 60_000,
  },
});
