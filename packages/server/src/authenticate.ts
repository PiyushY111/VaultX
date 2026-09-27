import type { FastifyRequest } from 'fastify';
import type pg from 'pg';
import { unauthorized } from './http-errors.js';
import { hashSessionToken } from './tokens.js';

declare module 'fastify' {
  interface FastifyRequest {
    /** Set by the authenticate hook on protected routes. */
    userId: string;
    /** The session the bearer token belongs to (sessions.id). */
    sessionId: string;
  }
}

/**
 * onRequest hook that resolves `Authorization: Bearer <token>` to
 * `request.userId` and `request.sessionId`, and records when the session was
 * last used. It runs before body parsing and validation, so unauthenticated
 * requests get a 401 without the body ever being read.
 */
export function createAuthenticate(pool: pg.Pool) {
  return async function authenticate(request: FastifyRequest): Promise<void> {
    const match = /^Bearer (\S+)$/.exec(request.headers.authorization ?? '');
    const tokenHash = match?.[1] ? hashSessionToken(match[1]) : null;
    if (!tokenHash) throw unauthorized();

    const { rows } = await pool.query<{ id: string; user_id: string }>(
      `UPDATE sessions SET last_used_at = now()
       WHERE token_hash = $1 AND expires_at > now()
       RETURNING id, user_id`,
      [tokenHash],
    );
    const session = rows[0];
    if (!session) throw unauthorized();
    request.userId = session.user_id;
    request.sessionId = session.id;
  };
}
