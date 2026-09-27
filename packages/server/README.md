# @password-manager/server

Fastify API that stores and returns only ciphertext. All key derivation and
encryption happens client-side (`@password-manager/crypto`); the server never
imports that package at runtime and never decrypts anything.

## Endpoints

| Method | Path               | Auth   | Purpose                                                           |
| ------ | ------------------ | ------ | ----------------------------------------------------------------- |
| POST   | `/signup`          | —      | Store email, KDF salt/params, auth hash, wrapped vault key        |
| POST   | `/prelogin`        | —      | Get KDF salt/params for an email (needed to derive the auth hash) |
| POST   | `/login`           | —      | Verify auth hash (constant-time), issue a bearer session token    |
| GET    | `/vault-key`       | Bearer | Wrapped vault key + nonce + KDF salt/params                       |
| GET    | `/vault-items`     | Bearer | All of the user's encrypted items                                 |
| POST   | `/vault-items`     | Bearer | Store an encrypted item                                           |
| PUT    | `/vault-items/:id` | Bearer | Replace an item's ciphertext (must use a fresh nonce)             |
| DELETE | `/vault-items/:id` | Bearer | Delete an item                                                    |

Binary fields are standard padded base64 in JSON.

## Running with Docker Compose

From the repo root:

```sh
cp .env.example .env    # set POSTGRES_PASSWORD and PRELOGIN_SECRET (openssl rand -base64 32)
docker compose up --build
```

The API listens on `127.0.0.1:${API_PORT:-3000}`. Migrations run on startup.

## Trying it with curl

`scripts/demo-client.mjs` does the client-side crypto so you can build valid
requests (run `npm run build:crypto` first). From `packages/server`, in bash:

```sh
API=http://127.0.0.1:3000
EMAIL=demo@example.com PW='my master password'

curl -s -X POST $API/signup -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs signup $EMAIL "$PW")"

PRELOGIN=$(curl -s -X POST $API/prelogin -H 'content-type: application/json' -d "{\"email\":\"$EMAIL\"}")
TOKEN=$(curl -s -X POST $API/login -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs login $EMAIL "$PW" "$PRELOGIN")" | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')

VAULT_KEY=$(curl -s $API/vault-key -H "authorization: Bearer $TOKEN")

ID=$(curl -s -X POST $API/vault-items -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs encrypt-item "$PW" "$VAULT_KEY" '{"site":"github.com","password":"hunter2"}')" \
  | node -pe 'JSON.parse(require("fs").readFileSync(0)).id')

curl -s -X PUT $API/vault-items/$ID -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs encrypt-item "$PW" "$VAULT_KEY" '{"site":"github.com","password":"n3w"}')"

ITEMS=$(curl -s $API/vault-items -H "authorization: Bearer $TOKEN")
node scripts/demo-client.mjs decrypt-items "$PW" "$VAULT_KEY" "$ITEMS"

curl -s -X DELETE $API/vault-items/$ID -H "authorization: Bearer $TOKEN" -w '%{http_code}\n'
```

## Tests

```sh
npm test -w @password-manager/server
```

Integration tests start a throwaway Postgres container via Testcontainers
(Docker must be running), or use `TEST_DATABASE_URL` if set.

## Configuration

`PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE` (or `DATABASE_URL`),
`PORT`, `HOST`, `LOG_LEVEL`, `SESSION_TTL_SECONDS`, `AUTH_RATE_LIMIT_MAX`,
`LOGIN_MAX_FAILURES`, `LOGIN_FAILURE_WINDOW_SECONDS`, `TRUST_PROXY`, `PRELOGIN_SECRET`. See `.env.example` at the repo root.
