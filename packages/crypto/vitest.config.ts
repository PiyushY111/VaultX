import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Argon2id in WASM is intentionally slow.
    testTimeout: 30_000,
  },
});
