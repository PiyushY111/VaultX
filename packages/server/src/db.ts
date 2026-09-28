import pg from 'pg';

/**
 * Creates a connection pool. Uses DATABASE_URL if set; otherwise node-postgres
 * reads the standard PGHOST / PGPORT / PGUSER / PGPASSWORD / PGDATABASE vars.
 */
export function createPool(env: NodeJS.ProcessEnv = process.env): pg.Pool {
  return new pg.Pool(env.DATABASE_URL ? { connectionString: env.DATABASE_URL } : {});
}

/** True for a unique-constraint violation, optionally only on the named constraint. */
export function isUniqueViolation(error: unknown, constraint?: string): boolean {
  const pgError = error as { code?: unknown; constraint?: unknown } | null;
  return (
    pgError?.code === '23505' && (constraint === undefined || pgError.constraint === constraint)
  );
}

/** Runs `fn` in a transaction on one pooled connection, committing if it resolves. */
export async function withTransaction<T>(
  pool: pg.Pool,
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
