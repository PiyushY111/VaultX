import { buildApp } from './app.js';
import { loadConfig, type Config } from './config.js';
import { createPool } from './db.js';
import { migrate } from './migrate.js';
import { prepareTotpSecrets } from './totp-reencrypt.js';

let config: Config;
try {
  config = loadConfig();
} catch (error) {
  // A configuration mistake: print just the message, not a stack trace.
  console.error(`Invalid configuration: ${(error as Error).message}`);
  process.exit(1);
}
const pool = createPool();
const app = await buildApp({ pool, config });

if (config.preloginSecretIsEphemeral) {
  app.log.warn(
    'PRELOGIN_SECRET is not set; using a random per-process secret. Fake /prelogin salts will change on restart, which reveals which emails are unregistered.',
  );
}

const applied = await migrate(pool);
if (applied.length) app.log.info({ applied }, 'applied database migrations');

// Before accepting requests: encrypt two-factor secrets stored in plaintext
// before migration 005, and check every stored one is under a configured key.
const totp = await prepareTotpSecrets(pool, config.totpKeys);
if (totp.updated) {
  app.log.info({ accounts: totp.updated }, 'encrypted legacy two-factor secrets');
}

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
