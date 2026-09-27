# Design

VaultX is a self-hosted, zero-knowledge password manager. "Zero-knowledge" here means
the server stores and serves only ciphertext and values derived one-way from
the master password. Every key that can decrypt vault data is derived or
generated on the client and never leaves it.

- `packages/crypto`: all cryptography (libsodium, via `libsodium-wrappers-sumo`).
- `packages/server`: Fastify + Postgres API that stores opaque blobs.
- `packages/web`: React web vault.
- `packages/extension`: Manifest V3 browser extension.

The threat analysis is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Key hierarchy

```
master password (never leaves the client)
  │  NFC-normalize, then Argon2id(password, kdf_salt, kdf_params)   [client]
  ▼
master key (32 bytes)
  │  HKDF-SHA256 extract (empty salt), then two independent expands:
  ├─ info "password-manager:v1:stretched-master-key" ─▶ stretched master key (32 bytes)   [client only]
  └─ info "password-manager:v1:auth-hash"            ─▶ auth hash (32 bytes)             [sent at signup/login]
                                                            │  SHA-256 with a domain prefix   [server]
                                                            ▼
                                                        users.auth_hash

vault key (32 random bytes from libsodium's CSPRNG, generated once at signup)
  │  XChaCha20-Poly1305(key = stretched master key, AAD "password-manager:v1:vault-key")
  ▼
encrypted vault key (48 bytes) + 24-byte nonce     ─▶ users.encrypted_vault_key, users.vault_key_nonce

item JSON {"v":1, site, username, password, notes}
  │  XChaCha20-Poly1305(key = vault key, AAD "password-manager:v1:item", fresh random nonce)
  ▼
item ciphertext (+16-byte tag) + 24-byte nonce     ─▶ vault_items.encrypted_data, vault_items.nonce
```

### Step by step

| Step                                   | Primitive                                                       | Where        | Notes                                                                                                                                                                                           |
| -------------------------------------- | --------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Master password → master key           | Argon2id (`crypto_pwhash`, `ALG_ARGON2ID13`)                    | Client       | 16-byte random salt per user. Defaults: 64 MiB, 3 passes, parallelism 1. Floor: 19 MiB, 2 passes (OWASP minimum). The password is NFC-normalized so that composed and decomposed Unicode match. |
| Master key → stretched key + auth hash | HKDF-SHA256 (RFC 5869) over HMAC-SHA256                         | Client       | Built on libsodium's HMAC because libsodium.js has no HKDF. The distinct `info` labels give domain separation.                                                                                  |
| Vault key                              | `crypto_aead_xchacha20poly1305_ietf_keygen`                     | Client, once | Random, not password-derived.                                                                                                                                                                   |
| Wrap vault key                         | XChaCha20-Poly1305                                              | Client       | Random 192-bit nonce; the AAD label stops a wrapped key being accepted as an item and vice versa.                                                                                               |
| Encrypt item                           | XChaCha20-Poly1305                                              | Client       | Fresh random nonce on every save; the server rejects a reused nonce.                                                                                                                            |
| Store auth hash                        | SHA-256(`"password-manager:server:auth-hash:v1\0"` ‖ auth hash) | Server       | Compared with `timingSafeEqual`.                                                                                                                                                                |
| Session token                          | 32 random bytes, base64url                                      | Server       | Only SHA-256(token) is stored. 24-hour TTL.                                                                                                                                                     |

`kdf_params` is stored per user as JSON (`{memoryCost, iterations, parallelism}`,
memoryCost in KiB), so costs can be raised for new accounts without breaking
existing ones. Clients refuse server-supplied parameters below the floor, so a
malicious server can't downgrade the KDF. libsodium's Argon2id is single-lane,
so `parallelism` must currently be 1. The field exists for forward
compatibility.

### Why a separate vault key?

The vault key is random and wrapped by the password-derived key rather than
being derived from the password itself:

- **Password change / KDF upgrade** only needs the vault key re-wrapped
  (one 48-byte blob), not every item re-encrypted. (Password change isn't
  implemented in v1, but the design allows it.)
- **The key that encrypts data is never reused for anything else.** The
  password-derived key only wraps one random key. This doesn't make a weak
  password safe: guessing the password unwraps the vault key and with it
  every item (see THREAT_MODEL.md). It does keep future changes, such as
  per-item keys or sharing, independent of the password.

## Why the auth hash is derived separately from the decryption key

The server must verify that a client knows the master password, but it must
never be able to decrypt the vault. If the client sent the key it decrypts
with, or anything the key could be computed from, the server would hold the
key. So one master key is split into two outputs that can't be computed from
each other:

1. **Independence.** The stretched master key and the auth hash are two HKDF
   expansions of the same PRK with different `info` strings. HKDF's outputs
   for different `info` values are computationally independent: knowing the
   auth hash gives no information about the stretched key, and there is no way
   to go from one to the other (or back to the master key) short of guessing
   the password. The server receives the auth hash only, so it can't unwrap
   the vault key. A unit test checks that the auth hash fails to decrypt the
   wrapped vault key.
2. **The expensive step happens before the split.** Both outputs come from the
   Argon2id result, so an attacker who captures the auth hash (on the wire,
   in server memory) still pays the full Argon2id cost per password guess.
   They gain no shortcut to the stretched key.
3. **The server hashes the auth hash again before storing it.** The auth hash
   is a login credential: whoever presents it can get a session (and with it,
   ciphertext). Storing SHA-256(auth hash) means a database dump can't be
   replayed to log in. A fast hash is enough because the auth hash is 256
   bits of uniform HKDF output, so there is no low-entropy input to
   brute-force at this layer.

The result: the server can authenticate users and throttle guessing, but what
it stores can't decrypt anything. Offline guessing of the master password
(Argon2id per guess) is the only attack left, and THREAT_MODEL.md covers it.

## Protocols

### Signup (client)

1. Generate a salt and choose `kdf_params` (defaults).
2. Derive master key → stretched key + auth hash.
3. Generate a vault key and wrap it under the stretched key.
4. `POST /signup {email, auth_hash, encrypted_vault_key, vault_key_nonce, kdf_salt, kdf_params}`.
5. The web client then calls `POST /login` with the same auth hash, so Argon2id doesn't run twice.

### Login / unlock (client)

1. `POST /prelogin {email}` → `{kdf_salt, kdf_params}`. For unknown emails the
   server returns a stable fake salt (HMAC of the email under
   `PRELOGIN_SECRET`) and default params, so this endpoint doesn't reveal
   which accounts exist.
2. Derive the keys locally; `POST /login {email, auth_hash}` → `{token, expires_at}`.
3. `GET /vault-key` → unwrap the vault key with the stretched key.
4. `GET /vault-items` → decrypt each item with the vault key.

Intermediate keys (master key, stretched key, auth hash) are zeroed as soon as
the vault key is unwrapped. Clients keep only the vault key and session token,
in memory.

### Login throttling (server)

- **Per IP:** 10 requests/minute to `/signup`, `/prelogin` and `/login`
  (`AUTH_RATE_LIMIT_MAX`).
- **Per account:** 5 failed logins per 15-minute fixed window
  (`LOGIN_MAX_FAILURES`, `LOGIN_FAILURE_WINDOW_SECONDS`).
  - Each attempt is counted atomically before the auth hash is checked, and a
    success clears the count.
  - Every 401 says how many attempts remain. Once locked, the server returns
    429 with `Retry-After` and a message giving the wait, and it doesn't
    check the auth hash, not even a correct one.
  - The limit applies to any submitted email, registered or not, so responses
    don't reveal account existence.

### Item writes

`POST /vault-items` and `PUT /vault-items/:id` take `{encrypted_data, nonce}`
and store the bytes unchanged. The server enforces:

- item ownership
- byte lengths (nonce 24, ciphertext ≥ 16 and ≤ 1 MiB)
- globally unique nonces
- no new content under an item's current nonce (an identical retry is allowed)

## Data model

### Server (Postgres, `packages/server/migrations/`)

All binary columns are `bytea` with length `CHECK`s. Schema changes are
numbered SQL migrations, applied on startup under an advisory lock.

**users**

| Column              | Type         | Contents                                                        |
| ------------------- | ------------ | --------------------------------------------------------------- |
| id                  | uuid PK      |                                                                 |
| email               | text, unique | Lower-cased.                                                    |
| kdf_salt            | bytea(16)    | Argon2id salt.                                                  |
| kdf_params          | jsonb        | `{memoryCost, iterations, parallelism}`.                        |
| auth_hash           | bytea(32)    | SHA-256 of the client's auth hash (never the auth hash itself). |
| encrypted_vault_key | bytea(48)    | Vault key + Poly1305 tag.                                       |
| vault_key_nonce     | bytea(24)    |                                                                 |
| created_at          | timestamptz  |                                                                 |

**vault_items**

| Column                 | Type                     | Contents               |
| ---------------------- | ------------------------ | ---------------------- |
| id                     | uuid PK                  |                        |
| user_id                | uuid FK → users, cascade |                        |
| encrypted_data         | bytea (≥16)              | Item ciphertext + tag. |
| nonce                  | bytea(24), unique        |                        |
| created_at, updated_at | timestamptz              |                        |

**sessions**

| Column     | Type                     | Contents                     |
| ---------- | ------------------------ | ---------------------------- |
| id         | uuid PK                  |                              |
| user_id    | uuid FK → users, cascade |                              |
| token_hash | bytea(32), unique        | SHA-256 of the bearer token. |
| expires_at | timestamptz              |                              |

**login_failures** (per-account throttling)

| Column            | Type        | Contents                                                     |
| ----------------- | ----------- | ------------------------------------------------------------ |
| email             | text PK     | As submitted (normalized), whether or not an account exists. |
| failure_count     | integer     | Unsuccessful attempts in the current window.                 |
| window_started_at | timestamptz |                                                              |

`schema_migrations` records which migration files have been applied.

What the server can see: email addresses, item count, the approximate size of
each item, timestamps, and request metadata (IP addresses, timing). It can't
see site names, usernames, passwords, notes or search queries.

### Client-side item format (inside the ciphertext)

```json
{ "v": 1, "site": "github.com", "username": "octocat", "password": "…", "notes": "…" }
```

`v` versions the format. The web vault and the extension share it, and a test
in the extension package checks the two stay compatible. `site` may be a bare
domain or a URL. The extension matches it by hostname: exact host or
subdomain, ignoring `www.`.

### Where clients keep secrets

|                          | Web vault                                             | Extension                                                                                                                                                                              |
| ------------------------ | ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vault key, session token | React state / refs (memory)                           | Service-worker memory, mirrored to `chrome.storage.session` (in-memory, cleared on browser close, not readable by content scripts), so the vault survives MV3 service-worker restarts. |
| Decrypted items          | Component state (memory)                              | Service-worker memory                                                                                                                                                                  |
| Persisted                | Auto-lock preference only (`localStorage`)            | Server URL, auto-lock preference, last email (`chrome.storage.local`)                                                                                                                  |
| Auto-lock                | 5 min inactivity (configurable 1–60)                  | 15 min without using the extension (configurable 5–60), OS screen lock, browser restart                                                                                                |
| On lock                  | Vault key zeroed, token dropped, vault view unmounted | Vault key zeroed, `chrome.storage.session` cleared                                                                                                                                     |

## Operational notes

- The API speaks plain HTTP and must be deployed behind a TLS-terminating
  reverse proxy. Docker Compose publishes it on `127.0.0.1` only.
- The web app calls same-origin `/api/*`. In development Vite proxies it; in
  production, serve the web build and the API behind the same proxy.
- Production builds of the web app ship a strict CSP: `script-src 'self'
'wasm-unsafe-eval'`, `connect-src 'self'`, with no inline scripts or styles.
