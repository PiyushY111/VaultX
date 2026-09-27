import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { copyFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MIGRATIONS_DIR, migrate } from '../src/migrate.js';
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
      '003_item_revisions_and_sessions.sql',
    ]);
    expect(await migrate(ctx.pool)).toEqual([]);
  });

  it('marks items that existed before 003 as revision 0, and keeps their sessions', async () => {
    const fresh = await createTestContext({}, { migrations: false });
    try {
      const dir = await mkdtemp(join(tmpdir(), 'migrations-'));
      for (const name of ['001_initial_schema.sql', '002_login_failures.sql']) {
        await copyFile(join(MIGRATIONS_DIR, name), join(dir, name));
      }
      await migrate(fresh.pool, dir);
      await fresh.pool.query(
        `WITH u AS (
           INSERT INTO users (email, kdf_salt, kdf_params, auth_hash, encrypted_vault_key, vault_key_nonce)
           VALUES ('old@example.com', $1, '{}', $2, $3, $4) RETURNING id
         ), i AS (
           INSERT INTO vault_items (user_id, encrypted_data, nonce) SELECT id, $3, $4 FROM u
         )
         INSERT INTO sessions (user_id, token_hash, expires_at)
         SELECT id, $2, now() + interval '1 hour' FROM u`,
        [Buffer.alloc(16), Buffer.alloc(32), Buffer.alloc(48), Buffer.alloc(24)],
      );
      expect(await migrate(fresh.pool)).toEqual(['003_item_revisions_and_sessions.sql']);
      const { rows: items } = await fresh.pool.query('SELECT revision FROM vault_items');
      expect(items).toEqual([{ revision: 0 }]);
      const { rows: sessions } = await fresh.pool.query(
        'SELECT client, user_agent, created_at IS NOT NULL AS has_created_at FROM sessions',
      );
      expect(sessions).toEqual([{ client: null, user_agent: null, has_created_at: true }]);
      // New rows must state their revision.
      await expect(
        fresh.pool.query(
          'INSERT INTO vault_items (user_id, encrypted_data, nonce) SELECT id, $1, $2 FROM users',
          [Buffer.alloc(48), Buffer.alloc(24, 1)],
        ),
      ).rejects.toThrow(/revision/);
    } finally {
      await fresh.close();
    }
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
      'sessions.created_at:timestamp with time zone',
      'sessions.last_used_at:timestamp with time zone',
      'sessions.client:text',
      'sessions.user_agent:text',
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
      'vault_items.revision:integer',
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
