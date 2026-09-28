# @password-manager/server

Fastify API that stores and returns only ciphertext. All key derivation and
encryption happens client-side (`@password-manager/crypto`); the server never
imports that package at runtime and never decrypts anything.

## Endpoints

| Method | Path                           | Auth   | Purpose                                                                     |
| ------ | ------------------------------ | ------ | --------------------------------------------------------------------------- |
| POST   | `/signup`                      | —      | Store email, KDF salt/params, auth hash, wrapped vault key                  |
| POST   | `/prelogin`                    | —      | Get KDF salt/params for an email (needed to derive the auth hash)           |
| POST   | `/login`                       | —      | Verify auth hash (constant-time), issue a bearer session token              |
| GET    | `/vault-key`                   | Bearer | Wrapped vault key + nonce + KDF salt/params                                 |
| GET    | `/vault-items`                 | Bearer | All of the user's encrypted items                                           |
| POST   | `/vault-items`                 | Bearer | Store an encrypted item (client-chosen id, revision 1)                      |
| PUT    | `/vault-items/:id`             | Bearer | Save the item's next revision (must use a fresh nonce)                      |
| DELETE | `/vault-items/:id`             | Bearer | Delete an item                                                              |
| POST   | `/logout`                      | Bearer | End this session                                                            |
| GET    | `/sessions`                    | Bearer | The account's live sessions (client, user agent, last used)                 |
| DELETE | `/sessions/:id`                | Bearer | End one session                                                             |
| DELETE | `/sessions`                    | Bearer | Sign out everywhere (every session, including this one)                     |
| POST   | `/account/password`            | Bearer | Change master password and rotate the vault key (see below)                 |
| POST   | `/vault-items/batch`           | Bearer | Create up to 500 items (an import) with one manifest change, all or nothing |
| PUT    | `/vault-manifest`              | Bearer | Write a vault's first manifest (see Vault manifest)                         |
| GET    | `/account`                     | Bearer | Email, two-factor status, recovery codes left                               |
| POST   | `/account/totp/setup`          | Bearer | Start two-factor setup: a new secret and `otpauth://` URI                   |
| POST   | `/account/totp/enable`         | Bearer | Confirm setup with the password and a code; returns recovery codes          |
| POST   | `/account/totp/disable`        | Bearer | Turn two-factor off (password + code)                                       |
| POST   | `/account/totp/recovery-codes` | Bearer | Replace the recovery codes (password + code)                                |
| DELETE | `/account`                     | Bearer | Delete the account and all its data (password, and a code if 2FA is on)     |

Binary fields are standard padded base64 in JSON.

### Item revisions

Each item's ciphertext is bound to its id and a revision number (both are in
the AEAD associated data), so the server can't swap two items' contents or
pass an old ciphertext off as the current one. The client chooses the id
(a lowercase UUID) and creates the item at revision 1; each `PUT` must send
exactly the current revision + 1, or it gets a 409 with `current_revision`.
Items saved before revisions existed are revision 0; clients decrypt them
with the old format and re-save them as revision 1.

### Vault manifest

Every item write (`POST`, `PUT` and `DELETE /vault-items`) must include
`manifest: {version, encrypted_data, nonce}`: the client's encrypted list of
every item id and revision, at exactly the stored version + 1. The server
can't read it; it applies the item change and the new manifest in one
transaction, or neither (409 with `manifest_version`). `GET /vault-items`
returns `{items, manifest}` from one snapshot, so clients can check the items
against it. A vault without one (created before migration 004) gets its
first from `PUT /vault-manifest`.

### Two-factor login

With two-factor on, `POST /login` needs `totp_code` (6 digits) or
`recovery_code` as well. The server says so (401 with `totp_required: true`)
only after the auth hash checks out, and that reply doesn't use up a login
attempt; wrong codes do. Each TOTP time step and each recovery code works
once. The TOTP secret is stored server-side (it has to be, to check codes);
it guards logging in, not the vault's encryption.

### Changing the master password

`POST /account/password` takes the current auth hash (to prove the old
password), the new auth hash, KDF salt and params, a **new** vault key wrapped
under the new password, and every item re-encrypted under that key at its
next revision. It's all-or-nothing: the item list must match the vault
exactly, or nothing changes (409). Wrong current passwords get a 403 and count
toward the same per-account lockout as failed logins. It also carries the
manifest, re-encrypted under the new vault key at the next version. On
success every other session is ended, since they hold the old vault key.

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

# Each write sends the vault's next encrypted manifest, computed from the current vault.
ITEMS=$(curl -s $API/vault-items -H "authorization: Bearer $TOKEN")
ITEM=$(curl -s -X POST $API/vault-items -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs encrypt-item "$PW" "$VAULT_KEY" "$ITEMS" '{"site":"github.com","password":"hunter2"}')")
ID=$(echo "$ITEM" | node -pe 'JSON.parse(require("fs").readFileSync(0)).id')

ITEMS=$(curl -s $API/vault-items -H "authorization: Bearer $TOKEN")
curl -s -X PUT $API/vault-items/$ID -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs update-item "$PW" "$VAULT_KEY" "$ITEMS" "$ITEM" '{"site":"github.com","password":"n3w"}')"

ITEMS=$(curl -s $API/vault-items -H "authorization: Bearer $TOKEN")
node scripts/demo-client.mjs decrypt-items "$PW" "$VAULT_KEY" "$ITEMS"

curl -s -X DELETE $API/vault-items/$ID -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "$(node scripts/demo-client.mjs delete-item "$PW" "$VAULT_KEY" "$ITEMS" "$ID")" -w '%{http_code}\n'
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
