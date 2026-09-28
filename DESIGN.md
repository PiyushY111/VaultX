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
  │  XChaCha20-Poly1305(key = vault key, fresh random nonce,
  │    AAD "password-manager:v2:item" ‖ 0x00 ‖ item id ‖ 0x00 ‖ revision)
  ▼
item ciphertext (+16-byte tag) + 24-byte nonce     ─▶ vault_items.encrypted_data, vault_items.nonce

vault manifest JSON {"v":1, version, items: {id: revision}, updated_at, updated_by}
  │  XChaCha20-Poly1305(key = vault key, fresh random nonce,
  │    AAD "password-manager:v1:manifest" ‖ 0x00 ‖ version)
  ▼
manifest ciphertext + 24-byte nonce                ─▶ users.encrypted_manifest, users.manifest_nonce
```

### Step by step

| Step                                   | Primitive                                                       | Where        | Notes                                                                                                                                                                                           |
| -------------------------------------- | --------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Master password → master key           | Argon2id (`crypto_pwhash`, `ALG_ARGON2ID13`)                    | Client       | 16-byte random salt per user. Defaults: 64 MiB, 3 passes, parallelism 1. Floor: 19 MiB, 2 passes (OWASP minimum). The password is NFC-normalized so that composed and decomposed Unicode match. |
| Master key → stretched key + auth hash | HKDF-SHA256 (RFC 5869) over HMAC-SHA256                         | Client       | Built on libsodium's HMAC because libsodium.js has no HKDF. The distinct `info` labels give domain separation.                                                                                  |
| Vault key                              | `crypto_aead_xchacha20poly1305_ietf_keygen`                     | Client, once | Random, not password-derived.                                                                                                                                                                   |
| Wrap vault key                         | XChaCha20-Poly1305                                              | Client       | Random 192-bit nonce; the AAD label stops a wrapped key being accepted as an item and vice versa.                                                                                               |
| Encrypt item                           | XChaCha20-Poly1305                                              | Client       | Fresh random nonce on every save; the server rejects a reused nonce. The AAD binds the item's id and revision (see Item writes).                                                                |
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

- **Password change / KDF upgrade** could be done by re-wrapping the vault
  key alone (one 48-byte blob). VaultX's password change goes further and
  rotates the vault key too (see Protocols), because a password you think
  is compromised may already have been used to unwrap the old one.
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

In the web vault Argon2id runs in a dedicated Web Worker
(`packages/web/src/vault/kdf.worker.ts`), so the page stays responsive during
the ~1 s, 64 MiB hash. The worker is created for one derivation, transfers the
two derived keys back, and is terminated. The extension already runs it in its
background service worker, off the popup's thread.

### Login / unlock (client)

1. `POST /prelogin {email}` → `{kdf_salt, kdf_params}`. For unknown emails the
   server returns a stable fake salt (HMAC of the email under
   `PRELOGIN_SECRET`) and default params, so this endpoint doesn't reveal
   which accounts exist.
2. Derive the keys locally; `POST /login {email, auth_hash, client}` → `{token, expires_at}`.
   `client` (`web` or `extension`) only labels the session in the session list.
3. `GET /vault-key` → unwrap the vault key with the stretched key.
4. `GET /vault-items` → decrypt each item with the vault key.

Intermediate keys (master key, stretched key, auth hash) are zeroed as soon as
the vault key is unwrapped. Clients keep only the vault key and session token,
in memory.

### Lock, log out and sessions

Locking or logging out calls `POST /logout`, which deletes that session
server-side (best effort: the client is locked either way). `GET /sessions`
lists the account's live sessions (client label, user agent, created, last
used), `DELETE /sessions/:id` ends one, and `DELETE /sessions` ends all of
them ("sign out everywhere").

### Changing the master password (client)

1. `GET /vault-key`, derive the current keys, and check locally that they
   unwrap the vault key (a typo shouldn't use up a login attempt).
2. Generate a new salt, derive new keys, and generate a **new vault key**.
3. Re-encrypt every item under the new vault key at its next revision.
4. `POST /account/password {current_auth_hash, auth_hash, kdf_salt,
kdf_params, encrypted_vault_key, vault_key_nonce, items, manifest}`, with the
   manifest at its next version, encrypted under the new vault key.

The server verifies the current auth hash (wrong ones count toward the
per-account login lockout), checks the item list is exactly the vault's
items at their next revisions, then in one transaction updates every item,
the user row, and deletes every other session. Anything else gets a 409 and
changes nothing. The client then swaps in the new vault key. It refuses to
start if any item failed a check (decryption or the manifest), since those
couldn't be re-encrypted.

### Two-factor login (TOTP)

RFC 6238: HMAC-SHA1, 6 digits, 30-second steps, ±1 step of drift, which
every authenticator app supports.

1. `POST /account/totp/setup` stores a new 20-byte secret as _pending_ and
   returns it (base32) with an `otpauth://` URI, which the web vault shows
   as a QR code.
2. `POST /account/totp/enable {current_auth_hash, totp_code}` checks the
   password and a code for the pending secret, turns it on, and returns ten
   one-time recovery codes (`XXXXX-XXXXX`, ~50 bits each; only SHA-256
   hashes are stored).
3. `POST /login` then also needs `totp_code` or `recovery_code`. The server
   answers `401 {totp_required: true}` only once the auth hash matched, and
   gives back the attempt that reply used; wrong codes count. The last
   accepted time step is stored, so a code works once, and a recovery code
   is deleted when used.

The web vault keeps the password-derived keys in memory while it asks for the
code (wiped after five minutes or on cancel), so Argon2id doesn't run twice;
the extension keeps them in the background worker's memory the same way.
Turning two-factor off, replacing recovery codes, and deleting the account
all take the master password (re-derived, and checked locally first) and a
code.

### Account deletion

`DELETE /account {current_auth_hash, totp_code?, recovery_code?}` deletes the
user row; items, sessions and recovery codes go with it (`ON DELETE
CASCADE`). The web vault asks for the email to be typed as confirmation, and
forgets its revision ledger for the account afterwards.

### Import

The web vault reads CSV exports in the browser and maps their columns to
items: Chrome/Edge/Brave (`name,url,username,password,note`), Firefox,
Bitwarden (logins only; cards, identities and notes are skipped) and
1Password. The site becomes the URL's host, which is what autofill matches;
TOTP secrets and differing names go into the notes, since there are no
fields for them yet. Logins already in the vault (same site, username and
password) are skipped. The rest are encrypted and sent with
`POST /vault-items/batch {items, manifest}`: up to 500 new items and one
manifest change in one transaction; bigger imports are several batches.

### Encrypted backups

Export writes one JSON file:

```json
{
  "format": "vaultx-backup",
  "version": 1,
  "created_at": "…",
  "kdf": { "salt": "…", "params": { "memoryCost": 65536, "iterations": 3, "parallelism": 1 } },
  "nonce": "…",
  "ciphertext": "…"
}
```

The key comes from the backup password (the master password unless another
is chosen) through the same Argon2id + HKDF derivation as logging in, with
the file's own fresh salt, so it's unrelated to the account's keys. The
ciphertext is XChaCha20-Poly1305 with AAD `password-manager:v1:backup` over
`{"v":1, "created_at", "items": [item JSON…]}`. Reading a backup refuses KDF
params below the floor, so an edited file can't make guessing cheap. Export
asks for the master password first, even when a separate backup password
is used.

### Breach check (opt-in)

The web vault's health report can check passwords against Have I Been
Pwned's Pwned Passwords with its k-anonymity range API
(`packages/web/src/lib/breachCheck.ts`): it sends the first five hex
characters of each password's SHA-1 hash to
`https://api.pwnedpasswords.com/range/<prefix>` (with `Add-Padding`, so
response sizes don't hint at the prefix), receives every known hash with that
prefix, and compares locally. Passwords sharing a prefix take one request;
requests run four at a time. It's off unless the user clicks the button, and
the production CSP allows that origin for it.

### Emergency kit

Offered right after signup and from the Security page: a text sheet to
print or download with the email, server address, and a blank line for the
master password to be written by hand. It never contains the password or
any key.

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

Every item ciphertext is bound to its **id** and a **revision** number, which
are part of the AEAD associated data. The client chooses the id (a random
lowercase UUID) before the first save, so it can encrypt with it.

- `POST /vault-items {id, revision: 1, encrypted_data, nonce}` creates an item.
- `PUT /vault-items/:id {revision, encrypted_data, nonce}` must send exactly
  the stored revision + 1, or gets a 409 with `current_revision`. This also
  stops a client with a stale copy overwriting a newer save.

The server stores the bytes unchanged and enforces:

- item ownership
- byte lengths (nonce 24, ciphertext ≥ 16 and ≤ 1 MiB)
- globally unique nonces
- no new content under an item's current nonce (an identical retry is allowed)
- the next-revision rule

Because of the binding, the server can't swap two items' contents or present
an old ciphertext as a newer revision: decryption fails. It could still serve
an old ciphertext **at its old revision**, so each client also keeps a
**revision ledger**: the highest revision it has seen per item id (web:
`localStorage`; extension: `chrome.storage.local`; ids and numbers only).
Items older than the ledger, or deleted items that reappear, are hidden and
reported as rolled back.

Items saved before this scheme (migration 003) are revision 0 and use the old
unbound AAD `password-manager:v1:item`. Clients can still decrypt them, but
never write revision 0; the web vault re-saves them as revision 1 when it
loads them.

### Vault manifest

The ledger only helps a device that has seen the vault before. The
**manifest** works on any device: an encrypted list of every item id and its
current revision, plus when and from which client the vault last changed
(`packages/crypto/src/manifest.ts`). Its version number is in its AAD.

- Every item write sends the next manifest along (`manifest: {version,
encrypted_data, nonce}`), at exactly the stored version + 1. The server
  can't read it; it stores it in the same transaction as the item change,
  or rejects both (409 with `manifest_version`). A client that gets that
  409 reloads the vault (the extension retries once by itself).
- `GET /vault-items` returns `{items, manifest}` from one database snapshot.
- On load, clients decrypt it and compare. Items it doesn't list (added, or
  deleted and brought back) and items at another revision (rolled back) are
  hidden; items it lists that weren't returned are reported as missing. A
  manifest that fails to decrypt, is older than one this device has seen,
  or has vanished is reported too.
- A vault with no manifest yet (created before migration 004) gets one from
  the first client that loads it (`PUT /vault-manifest`, trust on first use).

It can't prove to a device with no history that it's the _latest_ manifest,
so the web vault shows "last changed … from …" for a person to judge.

## Data model

### Server (Postgres, `packages/server/migrations/`)

All binary columns are `bytea` with length `CHECK`s. Schema changes are
numbered SQL migrations, applied on startup under an advisory lock.

**users**

| Column                             | Type                | Contents                                                        |
| ---------------------------------- | ------------------- | --------------------------------------------------------------- |
| id                                 | uuid PK             |                                                                 |
| email                              | text, unique        | Lower-cased.                                                    |
| kdf_salt                           | bytea(16)           | Argon2id salt.                                                  |
| kdf_params                         | jsonb               | `{memoryCost, iterations, parallelism}`.                        |
| auth_hash                          | bytea(32)           | SHA-256 of the client's auth hash (never the auth hash itself). |
| encrypted_vault_key                | bytea(48)           | Vault key + Poly1305 tag.                                       |
| vault_key_nonce                    | bytea(24)           |                                                                 |
| created_at                         | timestamptz         |                                                                 |
| manifest_version                   | integer             | 0 until the first manifest is written.                          |
| encrypted_manifest, manifest_nonce | bytea, nullable     | The client's encrypted vault manifest.                          |
| totp_secret                        | bytea(20), nullable | Two-factor secret, once turned on.                              |
| totp_pending_secret                | bytea(20), nullable | During setup, until confirmed with a code.                      |
| totp_last_step                     | bigint              | Last accepted TOTP time step (so codes work once).              |

**vault_items**

| Column                 | Type                     | Contents                                      |
| ---------------------- | ------------------------ | --------------------------------------------- |
| id                     | uuid PK                  |                                               |
| user_id                | uuid FK → users, cascade |                                               |
| revision               | integer (≥0)             | Bound into the AAD; 0 = saved before binding. |
| encrypted_data         | bytea (≥16)              | Item ciphertext + tag.                        |
| nonce                  | bytea(24), unique        |                                               |
| created_at, updated_at | timestamptz              |                                               |

**sessions**

| Column                   | Type                     | Contents                                           |
| ------------------------ | ------------------------ | -------------------------------------------------- |
| id                       | uuid PK                  |                                                    |
| user_id                  | uuid FK → users, cascade |                                                    |
| token_hash               | bytea(32), unique        | SHA-256 of the bearer token.                       |
| expires_at               | timestamptz              |                                                    |
| created_at, last_used_at | timestamptz              |                                                    |
| client                   | text, nullable           | `web` or `extension`, as the client said at login. |
| user_agent               | text (≤256), nullable    | As sent at login, for the session list.            |

**totp_recovery_codes**

| Column    | Type                     | Contents                                     |
| --------- | ------------------------ | -------------------------------------------- |
| user_id   | uuid FK → users, cascade |                                              |
| code_hash | bytea(32)                | SHA-256 of a recovery code (deleted on use). |

**login_failures** (per-account throttling)

| Column            | Type        | Contents                                                     |
| ----------------- | ----------- | ------------------------------------------------------------ |
| email             | text PK     | As submitted (normalized), whether or not an account exists. |
| failure_count     | integer     | Unsuccessful attempts in the current window.                 |
| window_started_at | timestamptz |                                                              |

`schema_migrations` records which migration files have been applied.

What the server can see: email addresses, item count, the approximate size of
each item, how many times each item has been saved (its revision), timestamps,
and request metadata (IP addresses, timing, user agents). It can't
see site names, usernames, passwords, notes or search queries.

### Client-side item format (inside the ciphertext)

```json
{ "v": 1, "site": "github.com", "username": "octocat", "password": "…", "notes": "…", "totp": "…" }
```

Optional fields, each left out of the JSON when unset so older items encrypt
exactly as before:

| Field      | Contents                                                                              |
| ---------- | ------------------------------------------------------------------------------------- |
| `type`     | `note`, `card` or `identity`; absent for a login. `site` is the title for those.      |
| `totp`     | The site's two-factor setup key or `otpauth://` link, as pasted (logins).             |
| `tags`     | Free-form labels, deduplicated case-insensitively.                                    |
| `favorite` | `true` to sort first in the vault.                                                    |
| `fields`   | Card details (`cardholder`, `number`, `expiry`, `cvv`) or identity details.           |
| `history`  | Earlier passwords, oldest first, each with when it was replaced; at most 10 (logins). |

The extension reads and preserves all of them but only offers logins (its
popup, autofill and save prompt ignore the other kinds). When the extension's
save prompt updates a password it records the old one in `history`, like the
web vault does.

`totp` is the site's two-factor setup key (base32) or `otpauth://` link, as
the user pasted it. It's left out of the JSON when empty, so items
without one encrypt exactly as before. Codes are computed on the client
(`packages/crypto/src/totp.ts`, RFC 6238 over WebCrypto HMAC; SHA-1/256/512,
6–8 digits, any period). In the extension the secret stays in the
background worker: the popup and content script only ever receive a code
and its remaining seconds, under the same rules as passwords (matching
host, https only, after a trusted click).

`v` versions the format. The web vault and the extension share it, and a test
in the extension package checks the two stay compatible. `site` may be a bare
domain or a URL. The extension matches it by hostname: exact host or
subdomain, ignoring `www.`.

### Where clients keep secrets

|                          | Web vault                                                                                                   | Extension                                                                                                                                                                              |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vault key, session token | React state / refs (memory)                                                                                 | Service-worker memory, mirrored to `chrome.storage.session` (in-memory, cleared on browser close, not readable by content scripts), so the vault survives MV3 service-worker restarts. |
| Decrypted items          | Component state (memory)                                                                                    | Service-worker memory                                                                                                                                                                  |
| Persisted                | Auto-lock preference and revision ledger (`localStorage`)                                                   | Server URL, auto-lock preference, last email, revision ledger (`chrome.storage.local`)                                                                                                 |
| Auto-lock                | 5 min inactivity (configurable 1–60)                                                                        | 15 min without using the extension (configurable 5–60), OS screen lock, browser restart                                                                                                |
| On lock                  | Vault key zeroed, token dropped and its server session ended, vault view unmounted, copied password cleared | Vault key zeroed, `chrome.storage.session` cleared, server session ended, copied password cleared                                                                                      |
| Copied passwords         | Cleared from the clipboard after 30 s                                                                       | Cleared after 30 s by the background worker (a `chrome.alarms` alarm plus an offscreen document), even after the popup closes                                                          |

## Operational notes

- The API speaks plain HTTP and must be deployed behind a TLS-terminating
  reverse proxy. Docker Compose publishes it on `127.0.0.1` only.
- The web app calls same-origin `/api/*`. In development Vite proxies it; in
  production, serve the web build and the API behind the same proxy.
- Production builds of the web app ship a strict CSP: `script-src 'self'
'wasm-unsafe-eval'`, `connect-src 'self'`, with no inline scripts or styles.
