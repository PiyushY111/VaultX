# VaultX

## Project overview

VaultX is a self-hosted, zero-knowledge password manager. You run the server; it stores
only ciphertext. Your master password, and every key that can decrypt your
vault, stay on your devices:

- **Your master password never leaves the client.** It's stretched with
  Argon2id, then split with HKDF into a key that decrypts your vault key and a
  separate _auth hash_ used only to log in. The server can check that auth hash
  but can't decrypt anything with it.
- **Every item is encrypted on the client** with XChaCha20-Poly1305 under a
  random vault key, with a fresh nonce on every save. Each ciphertext is
  bound to its item id and revision, so the server can't swap items or pass
  off old copies as current.
- **You can change your master password**, which also rotates the vault key
  and re-encrypts every item, and see or end every session.
- **The server stores opaque blobs.** Integration tests scan every raw
  database row to confirm no plaintext or key material is ever stored.

| Package                                    | What it is                                                                                                                                                 |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`packages/crypto`](packages/crypto)       | All cryptography (libsodium): Argon2id, HKDF, XChaCha20-Poly1305. Known-answer tests against independent implementations.                                  |
| [`packages/server`](packages/server)       | Fastify + Postgres API. Stores ciphertext, verifies auth hashes in constant time, throttles logins per IP and per account.                                 |
| [`packages/web`](packages/web)             | React + Vite web vault: signup, login, searchable vault, item editor, password generator, strength meter, auto-lock, master password change, session list. |
| [`packages/extension`](packages/extension) | Manifest V3 Chrome extension: popup vault, click-to-autofill, "save this password?" prompts, clipboard clearing.                                           |

- **How it works:** [DESIGN.md](DESIGN.md) (key hierarchy, protocols, data model).
- **What it protects against, and what it doesn't:** [THREAT_MODEL.md](THREAT_MODEL.md).

## Setup

### Prerequisites

- Node.js 22+ and npm
- Docker (with Compose v2) for the API and Postgres
- Google Chrome for the extension

### 1. Install dependencies

```sh
npm install
```

### 2. Start the API and database

```sh
cp .env.example .env
# Edit .env and set POSTGRES_PASSWORD and PRELOGIN_SECRET, e.g.:
#   openssl rand -base64 32
docker compose up -d --build
```

The API listens on `http://127.0.0.1:3000` (set `API_PORT` in `.env` to
change it) and applies database migrations on startup. It speaks plain HTTP
and is published on localhost only. For anything beyond local use, put it
behind a TLS-terminating reverse proxy.

### 3. Run the web vault

```sh
API_URL=http://127.0.0.1:3000 npm run dev -w @password-manager/web
```

Open http://localhost:5173 and create an account. The dev server proxies
`/api/*` to `API_URL`, so no CORS setup is needed. For production, build with
`npm run build -w @password-manager/web` and serve `packages/web/dist` and the
API behind one reverse proxy (`/api` → API).

### 4. Build and load the extension

```sh
npm run build -w @password-manager/extension
```

1. Open `chrome://extensions` and enable **Developer mode**.
2. **Load unpacked** → select `packages/extension/dist`.
3. Open the extension, go to **Settings**, set the server URL
   (`http://127.0.0.1:3000`), and unlock with the account you created in the
   web vault.
4. Visit a login page for a site you have saved. Click **Fill** in the prompt
   (nothing is filled without a click). Log in to a new site to get a
   "Save this password?" prompt.

### Tests

```sh
npm test -w @password-manager/crypto
npm test -w @password-manager/server        # needs Docker (starts a throwaway Postgres)
npm test -w @password-manager/web
npm test -w @password-manager/extension

# End-to-end, against the running API:
API_URL=http://127.0.0.1:3000 npm run test:e2e -w @password-manager/web        # uses installed Chrome
API_URL=http://127.0.0.1:3000 npm run test:e2e -w @password-manager/extension  # uses Playwright's Chromium
```

Repo-wide checks: `npm run lint`, `npm run format:check`,
`npm run typecheck`, `npm run build`.

## Future Work

These are deliberately out of scope for v1. Each would change the
cryptographic design or the trust model, not just add a feature.

- **Vault sharing (families, teams).** Sharing needs per-user public-key
  pairs, encrypting shared items (or collection keys) to each recipient,
  and handling membership changes. The hard part is trust: the server
  would hand out recipients' public keys, so a malicious server could
  substitute its own. That needs key verification (fingerprints or
  trust-on-first-use) that v1 doesn't have. It also depends on per-item or
  per-collection keys (below).
- **Mobile apps.** Native iOS/Android clients need platform secure storage
  (Keychain/Keystore), biometric unlock, and the OS autofill frameworks: a
  separate codebase and security review. Native clients would also fix a
  real weakness of the web vault, which has to trust whoever serves its
  JavaScript (THREAT_MODEL.md §1).
- **Breach monitoring.** Checking passwords against breach corpora (e.g.
  Have I Been Pwned's k-anonymity range API) means sending password-hash
  prefixes, and implicitly usage patterns, to a third party. Checking emails
  means disclosing them. For a zero-knowledge, self-hosted tool that's a
  privacy decision users should opt into explicitly, and it needs a design
  for doing the checks client-side without the server learning which
  passwords were checked.
- **Per-item keys.** v1 encrypts all items directly under one vault key.
  That's simple, but it means sharing a single item or rotating keys means
  re-encrypting everything, and a leaked vault key exposes the whole vault.
  Per-item keys (each wrapped by the vault key) enable sharing and granular
  rotation, but add a migration of every stored item and a more complex
  format. They're worth doing together with sharing, not before.

Other known gaps are documented in THREAT_MODEL.md and not yet scheduled:

- two-factor authentication
- a signed vault manifest, so a device that has never seen the vault can
  detect a stale copy (today rollback is caught only on devices that have
  seen a newer revision)
