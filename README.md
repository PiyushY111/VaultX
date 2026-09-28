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
- **An encrypted vault manifest** lists every item and revision, so any
  device can tell when the server hides, adds or rolls back items. A vault
  without one isn't trusted silently: you're asked to confirm it first. A
  **vault checkpoint** (version plus a fingerprint only your vault key can
  compute) lets you compare devices, or your emergency kit, to catch a
  server serving an older copy of the whole vault.
- **Optional two-factor login**: authenticator app codes, or **passkeys**,
  which can't be phished (with an option to require a passkey and turn
  authenticator codes off), plus recovery codes. Also **account deletion**,
  and a printable **emergency kit**. The
  server keeps two-factor secrets encrypted under a key held outside the
  database, so a leaked database or backup alone doesn't give them away (it
  doesn't help if the server itself is compromised; see THREAT_MODEL.md §2).
- **Import from Chrome, Firefox, Bitwarden or 1Password** (their CSV
  exports), and **export an encrypted backup** that restores into any
  VaultX account.
- **A password health report** flags weak, reused and old passwords,
  checked entirely on your device.
- **Two-factor codes for sites:** save a site's setup key with its login and
  the vault shows the live 6-digit code; the extension can fill it on the
  site's 2FA page.
- **Secure notes, cards and identities** alongside logins, with **tags and
  favorites**, and a **password history** kept inside each login.
- **Opt-in breach check** against Have I Been Pwned, sending only hash
  prefixes.
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
# Edit .env and set POSTGRES_PASSWORD, PRELOGIN_SECRET and
# TOTP_ENCRYPTION_KEY, each generated with:
#   openssl rand -base64 32
docker compose up -d --build
```

The API won't start without a valid `TOTP_ENCRYPTION_KEY` (it encrypts
two-factor secrets at rest). Keep it somewhere other than your database
backups, and don't lose it: without it, nobody with two-factor on can log in.
Upgrading an existing server? Add the key before restarting; on its first
start the server encrypts the two-factor secrets stored in plaintext by
earlier versions.

Passkeys also need `WEBAUTHN_RP_ID` (the domain the web vault is served
from, e.g. `vault.example.com`) and `WEBAUTHN_ORIGINS` (its exact origin,
e.g. `https://vault.example.com`). The server checks both at startup and
won't start without them. For local development, `.env.example` has
`localhost` and `http://localhost:5173`. Changing the RP ID later stops
every existing passkey working. Key rotation is described in
[packages/server/README.md](packages/server/README.md#two-factor-secret-encryption).

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
# The web suite's passkey test opens the vault at localhost:4173, so run the API with
# WEBAUTHN_RP_ID=localhost WEBAUTHN_ORIGINS=http://localhost:4173
API_URL=http://127.0.0.1:3000 npm run test:e2e -w @password-manager/web        # uses installed Chrome
API_URL=http://127.0.0.1:3000 npm run test:e2e -w @password-manager/extension  # uses Playwright's Chromium
```

Repo-wide checks: `npm run lint`, `npm run format:check`,
`npm run typecheck`, `npm run build`, and `npm run audit` (known advisories
in runtime dependencies; policy in SECURITY.md).

The test suites include seeded randomized (fuzz) tests for every parser of
untrusted input. `FUZZ_RUNS=<n>` runs more cases, and `FUZZ_SEED=<seed>`
replays the seed a failure prints.

Web builds are reproducible. `npm run verify-build -w @password-manager/web`
checks a build against published SHA256SUMS; the release process is in
[packages/web/README.md](packages/web/README.md#releases-and-verification).
This helps people who check. It doesn't protect anyone from a malicious
server who doesn't (THREAT_MODEL.md §1); the browser extension is the safer
client.

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

- proving to a brand-new device that it has the _latest_ copy of the vault
  (the manifest catches hidden, added and rolled-back items anywhere, but a
  whole consistent older copy can only be spotted by its "last changed" date)
- passkeys in the browser extension (it keeps TOTP and recovery codes; see
  THREAT_MODEL.md §5), and checking passkey attestation (any authenticator
  is accepted today)
