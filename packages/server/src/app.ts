import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import type pg from 'pg';
import { createAuthenticate } from './authenticate.js';
import type { Config } from './config.js';
import { BODY_LIMIT_BYTES } from './limits.js';
import { registerAccountRoutes } from './routes/account.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerVaultRoutes } from './routes/vault.js';

export interface AppOptions {
  pool: pg.Pool;
  config: Config;
  logger?: FastifyServerOptions['logger'];
}

export async function buildApp({ pool, config, logger }: AppOptions): Promise<FastifyInstance> {
  const app = Fastify({
    // Fastify's default request logging records method, URL and IP only —
    // never bodies or the Authorization header.
    logger: logger ?? { level: config.logLevel },
    trustProxy: config.trustProxy,
    bodyLimit: BODY_LIMIT_BYTES,
    // Validate exactly what was sent: no type coercion, no silently dropped fields.
    ajv: { customOptions: { coerceTypes: false, removeAdditional: false } },
  });

  await app.register(rateLimit, { global: false });

  app.decorateRequest('userId', '');
  app.decorateRequest('sessionId', '');

  app.setErrorHandler(
    (error: Error & { statusCode?: number; details?: Record<string, unknown> }, request, reply) => {
      const statusCode = error.statusCode ?? 500;
      if (statusCode >= 500) {
        request.log.error(error);
        return reply.code(500).send({
          statusCode: 500,
          error: 'Internal Server Error',
          message: 'Internal Server Error',
        });
      }
      return reply.code(statusCode).send({
        ...error.details,
        statusCode,
        error: errorName(statusCode),
        message: error.message,
      });
    },
  );

  registerAuthRoutes(app, pool, config);
  const authenticate = createAuthenticate(pool);
  registerVaultRoutes(app, pool, authenticate);
  registerAccountRoutes(app, pool, config, authenticate);

  return app;
}

function errorName(statusCode: number): string {
  const names: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    413: 'Payload Too Large',
    415: 'Unsupported Media Type',
    429: 'Too Many Requests',
  };
  return names[statusCode] ?? 'Error';
}
