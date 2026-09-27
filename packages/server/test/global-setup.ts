import { PostgreSqlContainer } from '@testcontainers/postgresql';
import type { TestProject } from 'vitest/node';

declare module 'vitest' {
  export interface ProvidedContext {
    /** Superuser connection URL; each test file creates its own database from it. */
    adminDatabaseUrl: string;
  }
}

/**
 * Starts a throwaway Postgres container for the test run. Set
 * TEST_DATABASE_URL to use an existing server instead (the role needs
 * CREATEDB).
 */
export default async function setup(project: TestProject) {
  if (process.env.TEST_DATABASE_URL) {
    project.provide('adminDatabaseUrl', process.env.TEST_DATABASE_URL);
    return;
  }
  const container = await new PostgreSqlContainer('postgres:17-alpine').start();
  project.provide('adminDatabaseUrl', container.getConnectionUri());
  return async () => {
    await container.stop();
  };
}
