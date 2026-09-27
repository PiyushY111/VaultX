import { randomBytes } from 'node:crypto';
import type { LoginThrottleConfig } from './login-throttle.js';

export interface Config {
  host: string;
  port: number;
  logLevel: string;
  /** Trust X-Forwarded-* headers (set when running behind a reverse proxy). */
  trustProxy: boolean;
  sessionTtlSeconds: number;
  /** Max requests per IP per minute to /signup, /prelogin and /login. */
  authRateLimitMax: number;
  /** Per-account limit on failed logins. */
  loginThrottle: LoginThrottleConfig;
  /** Keys the fake KDF salts that /prelogin returns for unknown emails. */
  preloginSecret: Buffer;
  /** True when PRELOGIN_SECRET was unset and a random per-process secret is in use. */
  preloginSecretIsEphemeral: boolean;
}

function readInt(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const preloginSecret = env.PRELOGIN_SECRET;
  return {
    host: env.HOST ?? '0.0.0.0',
    port: readInt(env, 'PORT', 3000),
    logLevel: env.LOG_LEVEL ?? 'info',
    trustProxy: env.TRUST_PROXY === 'true',
    sessionTtlSeconds: readInt(env, 'SESSION_TTL_SECONDS', 24 * 60 * 60),
    authRateLimitMax: readInt(env, 'AUTH_RATE_LIMIT_MAX', 10),
    loginThrottle: {
      maxFailures: readInt(env, 'LOGIN_MAX_FAILURES', 5),
      windowSeconds: readInt(env, 'LOGIN_FAILURE_WINDOW_SECONDS', 15 * 60),
    },
    preloginSecret: preloginSecret ? Buffer.from(preloginSecret, 'utf8') : randomBytes(32),
    preloginSecretIsEphemeral: !preloginSecret,
  };
}
