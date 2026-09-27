import pg from 'pg';

/**
 * Creates a connection pool. Uses DATABASE_URL if set; otherwise node-postgres
 * reads the standard PGHOST / PGPORT / PGUSER / PGPASSWORD / PGDATABASE vars.
 */
export function createPool(env: NodeJS.ProcessEnv = process.env): pg.Pool {
  return new pg.Pool(env.DATABASE_URL ? { connectionString: env.DATABASE_URL } : {});
}

export function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === '23505';
}
