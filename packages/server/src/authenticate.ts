import type { FastifyRequest } from 'fastify';
import type pg from 'pg';
import { unauthorized } from './http-errors.js';
import { hashSessionToken } from './tokens.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Set by the authenticate hook on protected routes. */
    userId: string;
  }
}

/**
 * onRequest hook that resolves `Authorization: Bearer <token>` to
 * `request.userId`. It runs before body parsing and validation, so
 * unauthenticated requests get a 401 without the body ever being read.
 */
export function createAuthenticate(pool: pg.Pool) {
  return async function authenticate(request: FastifyRequest): Promise<void> {
    const match = /^Bearer (\S+)$/.exec(request.headers.authorization ?? '');
    const tokenHash = match?.[1] ? hashSessionToken(match[1]) : null;
    if (!tokenHash) throw unauthorized();

    const { rows } = await pool.query<{ user_id: string }>(
      'SELECT user_id FROM sessions WHERE token_hash = $1 AND expires_at > now()',
      [tokenHash],
    );
    const session = rows[0];
    if (!session) throw unauthorized();
    request.userId = session.user_id;
  };
}
