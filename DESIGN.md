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
malicious server can't downgrade the KDF, and above a ceiling (1 GiB, 100
passes), so it can't make login run forever either. libsodium's Argon2id is single-lane,
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

#### Two-factor secrets at rest (server)

Unlike everything else the server stores, the TOTP secret is the server's
own: it generates it and has to read it back to check codes. Since
migration 005 both `totp_secret` and `totp_pending_secret` are encrypted
under a server key, `TOTP_ENCRYPTION_KEY` (`packages/server/src/totp-secret-box.ts`):

```
key id (1) ‖ nonce (12, random) ‖ AES-256-GCM(secret, 20 bytes) ‖ tag (16)   = 49 bytes
AAD = "password-manager:server:totp:v1" ‖ 0x00 ‖ user id ‖ 0x00 ‖ ("active" | "pending") ‖ 0x00 ‖ key id
```

- **Why AES-256-GCM from `node:crypto`**, not libsodium: the server doesn't
  load the client crypto package (a boundary test enforces that), and
  96-bit random nonces are safe here: at most two secrets per account per
  key, far below GCM's ~2^32-messages-per-key limit.
- **AAD binding.** A ciphertext only opens for the user and column it was
  written for, so someone who can write to the database can't copy another
  account's secret in, or turn a pending secret into the active one. For the
  same reason, `/account/totp/enable` decrypts the pending secret and
  encrypts it again for the active column rather than copying the bytes.
- **Keys and rotation.** `TOTP_ENCRYPTION_KEY` is a comma-separated list of
  base64 32-byte keys. The first encrypts; all of them decrypt. A key's id is
  the first byte of `SHA-256("password-manager:server:totp-key-id:v1" ‖ 0x00 ‖ key)`,
  so it doesn't depend on the key's position in the list, and putting a new
  key in front keeps the old ids valid. Startup refuses two keys with the
  same id (1 in 256 for a new key; generate another). To rotate: put the new
  key first, restart, run `npm run rotate-totp-key -w @password-manager/server`
  (idempotent; exits non-zero and lists any account it couldn't decrypt),
  then drop the old key and restart.
- **Required, validated at startup.** The server won't start without a
  well-formed key: each entry must be exactly 32 bytes of padded base64, not
  all zeros, and not repeated. There is no ephemeral fallback (unlike
  `PRELOGIN_SECRET`): a random key would lock every two-factor user out on
  the next restart. Error messages give a key's position, never its value.
- **Legacy secrets.** Rows written before migration 005 hold the raw 20
  bytes. SQL can't encrypt them (the key isn't in the database), so 005 only
  widens the `CHECK`s to allow 20 or 49 bytes. After migrating and before
  listening, the server encrypts every 20-byte value (idempotent, row-locked,
  safe with several instances starting at once). The read path still accepts
  a 20-byte value, so a row written by an old instance during a rolling
  upgrade keeps working until the next start re-encrypts it.
- **Unknown keys fail closed.** Startup refuses to run if any stored secret
  uses a key id that isn't configured (the old key was dropped before
  rotation finished), naming the ids and account counts. At request time, a
  secret that won't decrypt is a 500, never a successful or merely failed
  login.
- Decrypted secrets are zeroed (`Buffer.fill(0)`) after use. That is best
  effort: V8 may have copied them, and the keys themselves stay in memory for
  the life of the process.

Decisions taken where the requirements left room, choosing the more
conservative option:

- **Refuse to start** on keys missing from the keyring, rather than start
  and fail those accounts' logins.
- **Keep accepting legacy 20-byte values** on read. This doesn't weaken
  anything: someone who can write the database can already set
  `totp_secret` to `NULL`, which turns two-factor off for that account.
- The domain-separation labels live in `packages/server/src/totp-secret-box.ts`,
  next to the server's other labels (`tokens.ts`, `totp.ts`), not in
  `packages/crypto/src/constants.ts`, which is client-side libsodium code
  the server must not load.

### Passkeys (WebAuthn) as a second factor

A passkey is a phishing-resistant alternative to TOTP. Like TOTP it guards
logging in to the server (and account changes), never the vault's
encryption: the vault key still comes only from the master password. The
server stores only public keys and random challenges
(`packages/server/src/webauthn.ts`, using `@simplewebauthn/server`; the web
vault uses `@simplewebauthn/browser`).

**Ceremonies.** Every one uses a 32-byte random challenge stored in
`webauthn_challenges`, bound to one user and one purpose (`register`,
`login` or `reauth`), valid for 120 seconds, and deleted as it is checked
(`DELETE … RETURNING`, so each works once even under concurrent requests).
At most five are kept open per user and purpose. Every check requires the
origin to be one of `WEBAUTHN_ORIGINS`, the RP ID hash to match
`WEBAUTHN_RP_ID`, and **user verification** (a PIN or biometric, not just a
touch: `userVerification: 'required'`).

1. **Register.** `POST /account/passkeys/register/options` takes the master
   password and, if the account already has a second factor, one of those
   (through `verifyCurrentUser`, so wrong answers count toward the login
   lockout). It returns creation options; the challenge carries that proof
   to `POST /account/passkeys {name, response}`, which verifies the
   attestation and stores the credential. `attestation: 'none'`: any
   authenticator is accepted, and its make and model aren't checked. If this
   is the account's first second factor, the reply includes ten recovery
   codes.
2. **Log in.** After the auth hash matches, the "second factor needed" reply
   (`401 {totp_required: true, second_factor_methods, webauthn_options}`)
   carries fresh request options listing only this account's credentials.
   The client signs and sends the assertion as `webauthn` in the next
   `POST /login`. The credential is looked up by (user, credential id), so
   another account's passkey never verifies. A refused passkey counts as a
   failed attempt, and the reply carries a new challenge for the next try.
   Nothing about two-factor (not even whether passkeys exist) is revealed
   before the password is proven, exactly as for TOTP.
3. **Re-authenticate.** `POST /account/passkeys/reauth-options` gives a
   `reauth` challenge; the assertion goes in the `webauthn` field of any
   request that takes a second factor.

**Signature counter.** When a passkey reports a non-zero counter, it must
be higher than the stored one, or the assertion is refused as a possible
clone (and the user is told to use another factor and remove that passkey).
Updates are conditional (`sign_counter < new`), so two racing requests
can't both pass. Passkeys that always report 0 (most synced passkeys) are
accepted: for them, the counter can't detect cloning.

**"Require passkey".** `PUT /account/passkeys/required` (password + second
factor) sets `users.webauthn_required`. While it's on, TOTP codes are not
accepted as a second factor, for logging in or for account changes. The
TOTP secret itself is kept, so turning the option off restores it.
Recovery codes still work: they are the way back from a lost passkey.

**Deleting.** `DELETE /account/passkeys/:id` always takes the password and a
second factor. Deleting the last second factor (no other passkey, no TOTP)
turns two-factor off and deletes the recovery codes; the web vault warns
first. The only passkey can't be deleted while "Require passkey" is on
(409); turn that off first. Turning TOTP off keeps the recovery codes when
passkeys remain, since they back up every factor. Renaming (`PATCH`) takes
only the session: it changes a label.

**The extension doesn't do passkeys.** WebAuthn from an extension popup is
unreliable across browsers, and a passkey made for the web vault is bound
to the web vault's origin, not `chrome-extension://…`. So the extension
keeps TOTP and recovery codes. When the server's reply lists no `totp` (the
account is passkey-only, or has "Require passkey" on), the popup says the
account needs a passkey, points to the web vault, and offers a recovery
code. The cost: someone who only uses the extension with a passkey-only
account uses up a recovery code each time.

Decisions taken where the requirements left room, choosing the more
conservative option:

- **WEBAUTHN_RP_ID and WEBAUTHN_ORIGINS are required** (the server won't
  start without them) rather than passkeys being silently turned off. The
  RP ID must be a lowercase domain (no IP, scheme, port or path). Each
  origin must be exact (no path), use https (http only for `localhost`),
  and sit on the RP ID or a subdomain of it.
- **User verification is required**, for registration and every assertion.
- **"Require passkey" also applies to re-authentication**, not only to
  login: otherwise a phished TOTP code plus a stolen session could still
  remove the passkeys.
- **Adding a factor needs an existing factor.** Registering a passkey, or
  turning on TOTP when a passkey exists, takes one of the account's current
  second factors, not just the password.
- **One credential, one account**: `credential_id` is unique across users.
- **A counter that doesn't increase is refused**, not just logged.
- **Login doesn't need a separate "begin" call.** The "second factor
  needed" reply already requires the password, so it hands out the
  challenge; this keeps the rule "nothing before the password" in one place.

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

### Vault rate limits (server)

- **Per account, per route:** 120 requests/minute to each vault route
  (`VAULT_RATE_LIMIT_MAX`), and 20/minute to `/vault-items/batch`, which
  takes up to 64 MiB per request (`VAULT_BATCH_RATE_LIMIT_MAX`; 20 × 500
  items is still 10,000 items a minute for imports).
- Keyed on the account, not the IP or token, so a stolen token or a fresh
  session can't reset it. The limiter runs after authentication, so
  unauthenticated requests get a 401 without touching any account's budget.

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
- A new account's first manifest (version 1, empty) is written by the web
  vault right after signup (`PUT /vault-manifest`). The client created the
  vault, so there's nothing to confirm.

It can't prove to a device with no history that it's the _latest_ manifest,
so the web vault shows "last changed … from …" for a person to judge, and
both clients show a checkpoint (below) to compare.

#### No silent trust on first use

When a load finds no manifest the client can trust, it doesn't adopt the
server's items as the truth. This happens when there's no manifest at all
(`none`, a vault from before migration 004), when this device's ledger has
seen one and the server now has none (`missing`), or when the server's
manifest doesn't decrypt (`tampered`). Instead
(`packages/web/src/vault/sync.ts`, `packages/extension/src/background/vault.ts`):

- The vault loads **read-only**. What could be verified becomes the
  candidate baseline, at the version after the server's. Every write
  (create, update, delete, import, password change, re-saving legacy items)
  throws `BaselineRequiredError` before anything is sent.
- The user is shown the item count, the server's oldest and newest item
  dates (unauthenticated), the reason, and the version this device saw
  before, if any. Then: "Use this as the trusted baseline?"
- **Accepting** writes the candidate as the next manifest and records
  `{version, itemCount, reason, acceptedAt}` in the device's revision ledger
  (web: `localStorage` `password-manager.baseline:<email>`; extension:
  `chrome.storage.local` `baseline:<email>`). It also sets the ledger's seen
  manifest version to the baseline's, even if that's lower: the user chose
  to start over, and later loads shouldn't call the new baseline "stale".
- **Declining** ("Not now") keeps the vault read-only, writes nothing, and
  asks again on the next load.
- **In the extension**, a load can be started by a content script (a page
  asking for autofill matches), so loading never writes. Only the popup can
  send `acceptBaseline` (it's not in `CONTENT_REQUEST_TYPES`). A page's
  "save this password?" prompt fails with a message pointing to the popup,
  and keeps the captured credential until then.

Decisions where the requirements left room, taking the more conservative
option:

- The prompt also covers `missing` and `tampered` manifests, not only
  legacy vaults. Before this change those were repaired silently on the
  next write, which is the same trust-on-first-use.
- Signup writes the first manifest itself, instead of asking a new user to
  confirm an empty vault.
- A declined baseline blocks all writes, rather than allowing "just this
  one": any write moves the manifest on and would make the candidate the
  baseline.

#### Vault checkpoint

`packages/crypto/src/checkpoint.ts`. The version of the trusted manifest,
plus a fingerprint of its exact contents:

```
checkpoint key = HKDF-SHA256(vault key, info "password-manager:v1:checkpoint")   [32 bytes]
fingerprint    = first 80 bits of HMAC-SHA256(checkpoint key, JSON([version, [[id, revision], …sorted by id]]))
shown as       "42 · ABCD-EFGH-IJKL-MNOP"   (version · 16 base32 characters)
```

It covers exactly what the manifest proves (which items, at which
revisions), not the timestamp or client name, so every device with the same
manifest shows the same checkpoint. Comparing: equal versions must have
equal fingerprints (`match`, or `mismatch`); a checkpoint newer than this
device's manifest is a `rollback`; an older one is expected once the vault
has changed, and can't be checked further. The web vault shows it on the
Security page and prints it in the emergency kit; the extension shows it in
the popup. Both have a "Verify checkpoint" box. The key never leaves the
client, and without it the fingerprint can't be computed, tested or
brute-forced, so a server can't craft a different vault that shows the same
checkpoint. (80 bits is short enough to read aloud; the security rests on
the key, not on the length.)

## Data model

### Server (Postgres, `packages/server/migrations/`)

All binary columns are `bytea` with length `CHECK`s. Schema changes are
numbered SQL migrations, applied on startup under an advisory lock.

**users**

| Column                             | Type                | Contents                                                         |
| ---------------------------------- | ------------------- | ---------------------------------------------------------------- |
| id                                 | uuid PK             |                                                                  |
| email                              | text, unique        | Lower-cased.                                                     |
| kdf_salt                           | bytea(16)           | Argon2id salt.                                                   |
| kdf_params                         | jsonb               | `{memoryCost, iterations, parallelism}`.                         |
| auth_hash                          | bytea(32)           | SHA-256 of the client's auth hash (never the auth hash itself).  |
| encrypted_vault_key                | bytea(48)           | Vault key + Poly1305 tag.                                        |
| vault_key_nonce                    | bytea(24)           |                                                                  |
| created_at                         | timestamptz         |                                                                  |
| manifest_version                   | integer             | 0 until the first manifest is written.                           |
| encrypted_manifest, manifest_nonce | bytea, nullable     | The client's encrypted vault manifest.                           |
| totp_secret                        | bytea(49), nullable | Two-factor secret, once on; encrypted under TOTP_ENCRYPTION_KEY. |
| totp_pending_secret                | bytea(49), nullable | During setup, until confirmed with a code; encrypted likewise.   |
| totp_last_step                     | bigint              | Last accepted TOTP time step (so codes work once).               |
| webauthn_required                  | boolean             | "Require passkey": TOTP codes don't count as a second factor.    |

**webauthn_credentials**

| Column        | Type                     | Contents                                              |
| ------------- | ------------------------ | ----------------------------------------------------- |
| id            | uuid PK                  |                                                       |
| user_id       | uuid FK → users, cascade |                                                       |
| credential_id | bytea (1–1023), unique   | Chosen by the authenticator; unique across all users. |
| public_key    | bytea                    | COSE public key. Verifies signatures only.            |
| sign_counter  | bigint (0 – 2^32−1)      | Last counter seen; must increase when non-zero.       |
| transports    | text[]                   | Hints for the browser (`internal`, `usb`, …).         |
| name          | text (1–64)              | The user's label.                                     |
| created_at    | timestamptz              |                                                       |
| last_used_at  | timestamptz, nullable    |                                                       |

**webauthn_challenges**: `user_id`, `purpose` (`register` / `login` /
`reauth`), `challenge` (32 random bytes, unique), `created_at`,
`expires_at` (120 s). Deleted when used or expired.

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
- Production builds of the web app ship a strict CSP (`build/csp.ts`):
  `script-src 'self' 'wasm-unsafe-eval'`, `connect-src 'self'` plus Have I
  Been Pwned's range API, no inline scripts or styles, and Trusted Types
  (`require-trusted-types-for 'script'` with a single allowed policy, which
  only ever returns the KDF worker's URL). A `<meta>` CSP can't set
  `frame-ancestors`; send `Content-Security-Policy: frame-ancestors 'none'`
  (or `X-Frame-Options: DENY`) from the reverse proxy.

### Web build integrity

The web build is reproducible, and every build describes itself
(`packages/web/build/integrity-plugin.ts`):

- `dist/index.html` carries `integrity="sha384-…"` on its entry script and
  stylesheet. Icon links don't get one: browsers ignore integrity there, and
  an icon can't run code.
- `dist/SHA256SUMS` lists the SHA-256 of every file in the build, in
  `sha256sum -c` format, sorted by path. The **build hash** is the SHA-256 of
  that file.
- `dist/build-manifest.json` has the same hashes, the build hash, the SRI
  values, exact package versions from `package-lock.json`, the Node
  version, and the git commit and whether the tree had uncommitted changes
  (read with `git rev-parse HEAD` and `git --no-optional-locks status`, which
  don't write to the repository). It isn't in SHA256SUMS, because those
  details differ between builds of the same code.

**Reproducibility.** The build depends only on the source and the lockfile:
the bundle's dependencies are pinned to exact versions, output file names
are content hashes (set explicitly in `vite.config.ts`), and nothing embeds
a timestamp or a build path. `test/build-output.test.ts` builds twice and
checks the output is byte-identical and path-free.
`npm run verify-build` rebuilds in a fresh temporary directory with
`npm ci` and compares against a published SHA256SUMS. A different Node or
npm major version could still change the output; the manifest records the
Node version used.

**The Security panel's build hash** (`src/lib/buildInfo.ts`) is recomputed
by the page from `build-manifest.json`. The page also checks that the
script and stylesheet it loaded carry the SRI values the manifest lists.
What this can and can't show is in THREAT_MODEL.md §1: the page reports on
itself, so it can't catch deliberately modified code.

**Trusted Types.** The KDF worker used to be created with
`new Worker(new URL(…))`, a string-to-script sink. It is now created from
Vite's `?worker&url` import through the one allowed policy. The production
e2e suite runs under the enforced policy in Chrome and checks that the app
triggers no violations, that `innerHTML` from a string is refused, and that
no second policy can be created. Browsers without Trusted Types ignore
the directives.
