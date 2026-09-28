# @password-manager/server

Fastify API that stores and returns only ciphertext. All key derivation and
encryption happens client-side (`@password-manager/crypto`); the server never
imports that package at runtime and never decrypts anything.

## Endpoints

| Method | Path                                 | Auth   | Purpose                                                                     |
| ------ | ------------------------------------ | ------ | --------------------------------------------------------------------------- |
| POST   | `/signup`                            | —      | Store email, KDF salt/params, auth hash, wrapped vault key                  |
| POST   | `/prelogin`                          | —      | Get KDF salt/params for an email (needed to derive the auth hash)           |
| POST   | `/login`                             | —      | Verify auth hash (constant-time), issue a bearer session token              |
| GET    | `/vault-key`                         | Bearer | Wrapped vault key + nonce + KDF salt/params                                 |
| GET    | `/vault-items`                       | Bearer | All of the user's encrypted items                                           |
| POST   | `/vault-items`                       | Bearer | Store an encrypted item (client-chosen id, revision 1)                      |
| PUT    | `/vault-items/:id`                   | Bearer | Save the item's next revision (must use a fresh nonce)                      |
| DELETE | `/vault-items/:id`                   | Bearer | Delete an item                                                              |
| POST   | `/logout`                            | Bearer | End this session                                                            |
| GET    | `/sessions`                          | Bearer | The account's live sessions (client, user agent, last used)                 |
| DELETE | `/sessions/:id`                      | Bearer | End one session                                                             |
| DELETE | `/sessions`                          | Bearer | Sign out everywhere (every session, including this one)                     |
| POST   | `/account/password`                  | Bearer | Change master password and rotate the vault key (see below)                 |
| POST   | `/vault-items/batch`                 | Bearer | Create up to 500 items (an import) with one manifest change, all or nothing |
| PUT    | `/vault-manifest`                    | Bearer | Write a vault's first manifest (see Vault manifest)                         |
| GET    | `/account`                           | Bearer | Email, two-factor status, recovery codes left, passkey count                |
| POST   | `/account/totp/setup`                | Bearer | Start two-factor setup: a new secret and `otpauth://` URI                   |
| POST   | `/account/totp/enable`               | Bearer | Confirm setup with the password and a code; returns recovery codes          |
| POST   | `/account/totp/disable`              | Bearer | Turn two-factor off (password + code)                                       |
| POST   | `/account/totp/recovery-codes`       | Bearer | Replace the recovery codes (password + code)                                |
| POST   | `/account/passkeys/register/options` | Bearer | Begin adding a passkey (password + existing second factor)                  |
| POST   | `/account/passkeys`                  | Bearer | Finish adding a passkey; recovery codes if it's the first factor            |
| GET    | `/account/passkeys`                  | Bearer | List passkeys (name, transports, created, last used)                        |
| PATCH  | `/account/passkeys/:id`              | Bearer | Rename a passkey                                                            |
| DELETE | `/account/passkeys/:id`              | Bearer | Remove a passkey (password + second factor)                                 |
| POST   | `/account/passkeys/reauth-options`   | Bearer | A challenge to sign for an account change that needs a second factor        |
| PUT    | `/account/passkeys/required`         | Bearer | "Require passkey" on/off: TOTP stops counting (password + second factor)    |
| DELETE | `/account`                           | Bearer | Delete the account and all its data (password, and a second factor if on)   |

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

### Passkeys

Passkeys (WebAuthn) are a second factor alongside TOTP. After the password
checks out, `POST /login`'s `401 {totp_required: true}` reply also lists
`second_factor_methods` (`webauthn`, `totp`, `recovery_code`) and, if the
account has passkeys, `webauthn_options` for `navigator.credentials.get()`.
Send the result back as `webauthn` in the next `/login`. Account changes that
take a second factor accept `webauthn` as well, signed over a challenge from
`/account/passkeys/reauth-options`. Challenges work once, last two minutes,
and are bound to the account and to what they're for. User verification is
required, and a non-zero signature counter must increase. Details and
limits are in DESIGN.md → "Passkeys" and THREAT_MODEL.md §3.

`WEBAUTHN_RP_ID` (a domain, no scheme or port) and `WEBAUTHN_ORIGINS`
(comma-separated exact origins on that domain; https, or http for
localhost) are required; `WEBAUTHN_RP_NAME` defaults to `VaultX`.

### Two-factor secret encryption

`users.totp_secret` and `users.totp_pending_secret` are encrypted with
AES-256-GCM under `TOTP_ENCRYPTION_KEY` and bound to their user and column
(format in DESIGN.md → "Two-factor secrets at rest"). This protects the
secrets in a database dump or backup that doesn't include the server's
environment. It does **not** protect them from anyone who controls the
running server or can read its environment, since the key is there.

`TOTP_ENCRYPTION_KEY` is required: a comma-separated list of base64 32-byte
keys (`openssl rand -base64 32`). The first encrypts; all of them decrypt.
The server refuses to start if the value is missing or malformed, or if a
stored secret uses a key that isn't listed.

On startup, after migrations and before accepting requests, the server
encrypts any secrets still stored in plaintext by versions before migration 005. This is idempotent.

To rotate the key:

1. Put the new key first: `TOTP_ENCRYPTION_KEY=<new>,<old>`, and restart.
2. Re-encrypt everything under the new key, with the same environment:
   `npm run rotate-totp-key -w @password-manager/server` (in Docker:
   `docker compose exec api node dist/rotate-totp-key.js`). It's safe to run
   while the server is up and to re-run; it exits non-zero and lists any
   account it couldn't decrypt.
3. Once it reports no failures, remove `<old>` and restart.

Backups taken before step 2 still need the old key to read their two-factor
secrets.

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
cp .env.example .env    # set POSTGRES_PASSWORD, PRELOGIN_SECRET and TOTP_ENCRYPTION_KEY (openssl rand -base64 32),
                        # and WEBAUTHN_RP_ID / WEBAUTHN_ORIGINS to where the web vault is served
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
`VAULT_RATE_LIMIT_MAX`, `VAULT_BATCH_RATE_LIMIT_MAX`,
`LOGIN_MAX_FAILURES`, `LOGIN_FAILURE_WINDOW_SECONDS`, `TRUST_PROXY`, `PRELOGIN_SECRET`,
`TOTP_ENCRYPTION_KEY` (required; see above), `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS`
(required), `WEBAUTHN_RP_NAME`. See `.env.example` at the repo root.
