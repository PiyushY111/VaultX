import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate } from '../src/migrate.js';
import { createTestContext, type TestContext } from './helpers.js';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await createTestContext();
});

afterAll(async () => {
  await ctx?.close();
});

describe('migrations', () => {
  it('records applied migrations and is idempotent', async () => {
    const { rows } = await ctx.pool.query('SELECT name FROM schema_migrations ORDER BY name');
    expect(rows.map((row) => row.name)).toEqual([
      '001_initial_schema.sql',
      '002_login_failures.sql',
    ]);
    expect(await migrate(ctx.pool)).toEqual([]);
  });

  it('is safe to run concurrently', async () => {
    const results = await Promise.all([migrate(ctx.pool), migrate(ctx.pool), migrate(ctx.pool)]);
    expect(results).toEqual([[], [], []]);
  });

  it('creates the expected columns', async () => {
    const { rows } = await ctx.pool.query<{
      table_name: string;
      column_name: string;
      data_type: string;
    }>(
      `SELECT table_name, column_name, data_type FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name IN ('users', 'vault_items', 'sessions')
       ORDER BY table_name, ordinal_position`,
    );
    const columns = rows.map((row) => `${row.table_name}.${row.column_name}:${row.data_type}`);
    expect(columns).toEqual([
      'sessions.id:uuid',
      'sessions.user_id:uuid',
      'sessions.token_hash:bytea',
      'sessions.expires_at:timestamp with time zone',
      'users.id:uuid',
      'users.email:text',
      'users.kdf_salt:bytea',
      'users.kdf_params:jsonb',
      'users.auth_hash:bytea',
      'users.encrypted_vault_key:bytea',
      'users.vault_key_nonce:bytea',
      'users.created_at:timestamp with time zone',
      'vault_items.id:uuid',
      'vault_items.user_id:uuid',
      'vault_items.encrypted_data:bytea',
      'vault_items.nonce:bytea',
      'vault_items.created_at:timestamp with time zone',
      'vault_items.updated_at:timestamp with time zone',
    ]);
  });

  it('enforces byte-length constraints at the database level', async () => {
    await expect(
      ctx.pool.query(
        `INSERT INTO users (email, kdf_salt, kdf_params, auth_hash, encrypted_vault_key, vault_key_nonce)
         VALUES ('x@example.com', '\\x00', '{}', '\\x00', '\\x00', '\\x00')`,
      ),
    ).rejects.toThrow(/check constraint/);
  });
});
