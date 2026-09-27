import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createPool } from './db.js';
import { migrate } from './migrate.js';

const config = loadConfig();
const pool = createPool();
const app = await buildApp({ pool, config });

if (config.preloginSecretIsEphemeral) {
  app.log.warn(
    'PRELOGIN_SECRET is not set; using a random per-process secret. Fake /prelogin salts will change on restart, which reveals which emails are unregistered.',
  );
}

const applied = await migrate(pool);
if (applied.length) app.log.info({ applied }, 'applied database migrations');

app.addHook('onClose', async () => {
  await pool.end();
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    app.log.info({ signal }, 'shutting down');
    app.close().then(
      () => process.exit(0),
      (error: unknown) => {
        app.log.error(error);
        process.exit(1);
      },
    );
  });
}

await app.listen({ host: config.host, port: config.port });
