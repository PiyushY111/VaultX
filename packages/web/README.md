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
  live in memory only. localStorage holds the auto-lock preference and the
  revision ledger (item ids and revision numbers, used to spot rollbacks).
- **Locking** (manual, auto-lock, or an expired session) zeroes the vault key,
  ends the server session, clears a copied password from the clipboard, and
  unmounts the vault view so all decrypted items are released. Unlocking
  requires the master password and runs the full login flow again.
- **Argon2id runs in a Web Worker** (`src/vault/kdf.worker.ts`), so the page
  doesn't freeze while keys are derived.
- **Strength meter:** zxcvbn (loaded on demand, runs locally) rates passwords
  as you type. Master passwords must score at least "Strong"; item passwords
  get advice only.
- **Copied passwords** are cleared from the clipboard after 30 seconds.
- **Security page:** change the master password (rotates the vault key and
  re-encrypts every item), list sessions, and sign out one or all of them.
- **Rollback and swap detection:** items are bound to their id and revision
  and checked against the vault's encrypted manifest (`src/vault/sync.ts`);
  anything that fails to decrypt, doesn't match the manifest, or is older
  than this browser has seen is hidden and reported. The vault shows when it
  last changed.
- **Two-factor login** is set up on the Security page (QR code, recovery
  codes); the login form asks for the code only after the password is right.
- **Passkeys** (`src/lib/passkeys.ts`, `src/components/PasskeysSection.tsx`)
  are added, renamed and removed on the Security page, with an option to
  require one (TOTP codes then stop working). The login form offers the
  passkey first, then TOTP if it's still allowed, then a recovery code.
  Adding or removing a passkey takes the master password and an existing
  second factor. The passkey never leaves the authenticator; the page only
  passes the server's challenge to the browser and the signature back.
- **Delete account** (Security page) needs the email typed out, the master
  password, and a second factor (passkey, or a code) if one is on.
- **Emergency kit:** offered after signup and from the Security page, to
  print or download. It never contains the master password.
- **Two-factor codes** (`src/lib/useTotp.ts`): an item's setup key or
  `otpauth://` link is validated in the form (with the current code shown to
  check against the site) and the list shows the live code with a countdown
  and Copy. Imports put Bitwarden and 1Password TOTP secrets in this field.
- **Item kinds:** logins, secure notes, cards and identities share one
  encrypted format (`src/vault/items.ts`), with tags, favorites (sorted
  first, filterable by chips) and, for logins, a password history kept inside
  the item and shown in the edit form.
- **Breach check** (`src/lib/breachCheck.ts`): opt-in from the health page,
  Have I Been Pwned's k-anonymity range API; only hash prefixes are sent.
- **Password health** (`src/lib/passwordHealth.ts`): flags weak passwords
  (zxcvbn below "Strong", with the site and username as context), passwords
  shared by several logins, and logins not saved in over a year. It runs
  over the decrypted items in memory and sends nothing; the report never
  shows the passwords. ("Old" uses the item's last save, since password
  changes aren't recorded separately.)
- **Import / export:** CSV exports from Chrome (Edge, Brave), Firefox,
  Bitwarden and 1Password are parsed in the browser (`src/vault/importers.ts`),
  previewed, de-duplicated against the vault, encrypted, and saved in
  batches of 500. Exports are encrypted backup files (`src/vault/backup.ts`)
  protected by the master password or a separate backup password.
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
The passkey test uses Chrome's virtual authenticator and opens the vault at
`http://localhost:4173` (WebAuthn doesn't accept IP addresses), so the API
needs `WEBAUTHN_RP_ID=localhost WEBAUTHN_ORIGINS=http://localhost:4173`.
