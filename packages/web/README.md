# @password-manager/web

React + Vite web vault. All key derivation and encryption runs in the browser
via `@password-manager/crypto`; the server only ever receives the auth hash and
ciphertext.

## Running locally

```sh
# 1. Start the API + Postgres (from the repo root; see .env.example)
docker compose up -d --build

# 2. Start the web app (from the repo root)
API_URL=http://127.0.0.1:3000 npm run dev -w @password-manager/web
```

Open http://localhost:5173. The dev server proxies `/api/*` to `API_URL`, so
the app and API share an origin and no CORS is needed. In production, serve
`dist/` and the API behind one reverse proxy the same way (`/api` → API).

## Security properties

- **Nothing secret is sent.** Signup sends the email, KDF salt/params, auth hash,
  and wrapped vault key. Login sends the email and auth hash. Items are sent as
  XChaCha20-Poly1305 ciphertext.
- **Nothing secret is persisted.** The session token, vault key and decrypted items
  live in memory only. The only localStorage entry is the auto-lock preference.
- **Locking** (manual, auto-lock, or an expired session) zeroes the vault key,
  drops the token, and unmounts the vault view so all decrypted items are released.
  Unlocking requires the master password and runs the full login flow again.
- **Search** runs over decrypted items in memory and never touches the network.
- **KDF downgrade protection:** the client refuses server-supplied KDF params below
  the crypto package's floor.
- **Production CSP:** `script-src 'self' 'wasm-unsafe-eval'`, `connect-src 'self'`,
  no inline scripts or styles.

## Tests

```sh
npm test -w @password-manager/web                       # unit + flow tests (jsdom)
API_URL=http://127.0.0.1:3000 npm run test:e2e -w @password-manager/web   # real Chrome + real API
```

The end-to-end tests build the production bundle, run it with `vite preview`,
and need the API running (`docker compose up`) and Google Chrome installed.
