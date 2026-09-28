# Threat Model

This document states what the system defends against, how, and what it
explicitly does not defend against. The key hierarchy and protocols it refers
to are described in [DESIGN.md](DESIGN.md).

## Assets

| Asset                                                     | Where it exists                                                         |
| --------------------------------------------------------- | ----------------------------------------------------------------------- |
| Vault contents (sites, usernames, passwords, notes)       | Plaintext only in client memory; ciphertext on the server               |
| Master password                                           | Typed into the client; never stored or transmitted                      |
| Master key, stretched master key                          | Client memory, briefly during unlock                                    |
| Vault key                                                 | Client memory while unlocked (extension: also `chrome.storage.session`) |
| Auth hash                                                 | Sent to the server at signup/login; the server stores only a hash of it |
| Session token                                             | Client memory; the server stores only a hash of it                      |
| Metadata (emails, item counts and sizes, timestamps, IPs) | Server and database, in the clear                                       |

## Trust boundaries

1. **Client ↔ server.** The server is untrusted for confidentiality: it
   should learn nothing that decrypts the vault. It is trusted for
   availability and, in part, for integrity (see ciphertext replay).
2. **Web app code delivery.** Whoever serves the web app's JavaScript
   controls the web client. This is the weakest boundary in the system
   (see below).
3. **Extension background ↔ content scripts ↔ web pages.** The background
   service worker holds the vault key. Content scripts run inside untrusted
   pages and receive at most one credential, for the page's own domain, after
   a user click. Details are in the comment block at the top of
   `packages/extension/src/content/index.ts`.
4. **Browser / OS.** Everything here assumes the browser and OS are not
   compromised.

---

## 1. Malicious or compromised server operator

The operator can read and modify the database, change server code, and watch
all traffic that reaches the server.

**Mitigations**

- Zero-knowledge key hierarchy: the server receives only the auth hash,
  wrapped vault key, KDF salt/params and item ciphertexts. None of these
  decrypts anything. The auth hash and the decryption key are independent
  HKDF outputs (DESIGN.md explains why).
- AEAD (XChaCha20-Poly1305) on every item and on the wrapped vault key: the
  server can't modify ciphertext without decryption failing on the client.
  Both the web vault and the extension hide undecryptable items and warn
  that they may have been tampered with.
- KDF downgrade protection: clients refuse `kdf_params` below the floor
  (19 MiB / 2 passes), so the server can't make offline guessing cheaper by
  serving weak parameters at login.
- The extension's code is installed locally and doesn't come from the
  vault server, so a malicious operator can't change it.

**Not solved**

- **Malicious web app code.** If the operator also serves the web app (the
  normal self-hosted setup), they can ship JavaScript that captures the
  master password or decrypted items. Nothing in the web client can defend
  against the party that serves it; this is the fundamental limit of
  browser-delivered end-to-end encryption. The CSP limits _third-party_
  script injection, not the operator. Mitigations for later: subresource
  integrity with published hashes, reproducible builds, or using only the
  extension (or a future native app) as the client.
- **Offline guessing.** The operator holds everything needed to test
  password guesses: salt, params, and the wrapped vault key or the stored
  auth-hash hash. Each guess costs one Argon2id evaluation (64 MiB by
  default). A weak master password will fall; see §3.
- **Metadata.** Email addresses, number of items, approximate item sizes
  (ciphertext length = plaintext length + 16), timestamps and access
  patterns are all visible.
- **Availability and integrity of the vault as a whole.** The operator can
  refuse writes or delete the account. Hiding, adding, swapping or rolling
  back individual items is detected on any device (the vault manifest, §7).
  What it can still do is serve a whole, consistent older copy of the vault
  to a device that hasn't seen a newer one; the vault shows when it last
  changed, so a person can notice.
- **The two-factor secret is on the server.** It has to be, to check codes.
  It is encrypted at rest (§2), but under a key in the server's own
  environment, so the operator, or anyone who controls the running server,
  can decrypt it and generate codes. Passkeys don't change this: the server
  holds only their public keys, but the operator can add a credential of
  their own to any account, or run code that skips the check. Two-factor,
  TOTP or passkey, doesn't protect against the operator. It protects the
  vault's ciphertext from someone who only has the password or auth hash.
- **Session metadata.** The session list stores each login's user agent and
  when it was last used.

## 2. Database breach

An attacker obtains a copy of the Postgres database (or a backup) but doesn't
control the running server.

**Mitigations**

- No plaintext vault data, no keys. Integration tests scan every cell of
  every table for master passwords, item plaintext, key material, raw auth
  hashes and session tokens (raw, base64, base64url, hex) and find none.
- `users.auth_hash` is SHA-256 of the client's auth hash, so a dump can't be
  replayed to log in (tested: presenting the stored value fails).
- `sessions.token_hash` is SHA-256 of the bearer token, so stolen rows
  can't be used as sessions.
- Items are encrypted under a random 256-bit vault key; the only way in is
  through the master password (Argon2id).
- **Passkey rows are useless to a thief.** `webauthn_credentials` holds
  public keys, which only verify signatures, and `webauthn_challenges` holds
  random single-use values that expire in two minutes. A dump doesn't let
  anyone sign as a passkey.
- **Two-factor secrets are encrypted** (AES-256-GCM, since migration 005)
  under `TOTP_ENCRYPTION_KEY`, which is kept in the server's environment, not
  in the database. A database dump or backup on its own doesn't let the
  attacker generate codes. Each ciphertext is bound to its user and column,
  so write access to the database can't move one account's secret into
  another. The leak tests also look for every TOTP secret (raw, base32,
  base64, base64url, hex) and find none.

**Not solved**

- **Offline guessing of weak master passwords**, as in §1. The breach gives
  the attacker unlimited offline attempts; throttling doesn't apply.
- **Metadata exposure**, as in §1.
- **Backups and logs** are the operator's responsibility. The API doesn't
  log request bodies or `Authorization` headers.
- **Two-factor encryption only helps if the key isn't leaked with the
  data.** It protects against a leak of the database alone. It doesn't
  protect against:
  - full server compromise: the key is in the process environment and
    memory, so an attacker with code execution or the environment has it;
  - a backup that bundles the database with the server's environment or
    `.env` file;
  - an attacker who can write to the database: they can't forge a working
    secret, but they can set `totp_secret` to `NULL` (or insert a passkey
    public key of their own into `webauthn_credentials`), which gets past
    two-factor for that account. They still need the master password to log
    in, and nothing here helps them decrypt the vault;
  - old dumps: a copy taken before migration 005 (or before the server first
    restarted after it) holds raw secrets. Rotating the key doesn't change
    the secrets themselves, so for that the fix is users re-enrolling their
    authenticator;
  - a retired key: rotation re-encrypts the stored rows, but backups made
    before it still open with the old key. Treat a retired key as secret for
    as long as those backups exist.

## 3. Weak master password

**Mitigations**

- **Memory-hard KDF:** Argon2id at 64 MiB and 3 passes by default makes each
  guess expensive, especially on GPUs and ASICs. Per-user salts prevent
  precomputation and cross-user attacks.
- **Minimum length and strength:** the web client requires at least 12
  characters, a zxcvbn score of at least 3 ("Strong") at signup and on
  password change, and a confirmation field (a typo means permanent
  lockout). zxcvbn (via zxcvbn-ts) runs locally and is given the email as
  context, so passwords built from common words, keyboard patterns, dates or
  the user's own address are refused. Item passwords get the same meter as
  advice only.
- **Two-factor login (TOTP):** users can require a 6-digit code from an
  authenticator app, with ten one-time recovery codes (stored as hashes).
  The server only mentions it after the password checks out, so it reveals
  nothing to someone without the password. Wrong codes count toward the
  per-account lockout, each code works once, and turning it off, getting new
  recovery codes or deleting the account needs the password and a code.
- **Passkeys (WebAuthn):** a phishing-resistant second factor. The browser
  signs only for the origin the passkey was made on, and the server checks
  that origin against `WEBAUTHN_ORIGINS`, and the RP ID. So a lookalike site
  that relays the password in real time can't get a usable passkey
  signature, the way it can relay a TOTP code. Each signature covers a
  single-use, two-minute challenge bound to the account and to its purpose
  (login, re-authentication or registration), so it can't be replayed or
  spent elsewhere. User verification (PIN or biometric) is required.
  Counters that go backwards are refused as possible clones. "Require
  passkey" turns TOTP off as a factor, for login and account changes.
- **Master password change** re-derives everything from a new password and
  rotates the vault key, re-encrypting every item (see §7 for why rotation,
  not just re-wrapping). Other sessions are ended.
- **Online guessing is throttled on two levels:**
  - Per IP: 10 login requests per minute.
  - Per account: 5 failed logins per 15 minutes. Further attempts get a clear
    429 with `Retry-After`. It's counted atomically before verification, so
    parallel requests can't bypass it, and it applies to unknown emails too,
    so it doesn't reveal which accounts exist.

**Not solved**

- **Offline guessing after a breach** (§1, §2) is limited only by Argon2id
  and password entropy. A 12-character password drawn from a small space is
  still guessable.
- **The server can't enforce password strength.** It never sees the password,
  so the length and zxcvbn checks are client-side only, and a modified
  client can bypass them. zxcvbn is an estimate: a password it rates
  "Strong" can still be weak if it's reused or was leaked elsewhere.
- **Changing the password doesn't protect data an attacker already has.** If
  they captured the old wrapped vault key or item ciphertexts, the old
  password still opens those copies; rotation protects everything saved
  afterwards.
- **Two-factor login is optional**, and protects server access to the
  ciphertext, not the offline attack: someone with a database copy can guess
  passwords against it whether or not two-factor is on. (Encrypting the
  secrets at rest doesn't change that: guessing the master password offline
  never involves the second factor.) TOTP codes can also
  be phished in real time, like any code a person types in.
- **Passkeys are only as phishing-resistant as the weakest factor left on
  the account.** Without "Require passkey", a phisher can ask for a TOTP
  code instead. Even with it, **recovery codes can be phished**: they are
  typed in, like TOTP codes. Keeping them offline is the user's job.
- **What passkeys don't check:**
  - **Attestation isn't verified** (`attestation: 'none'`), so any
    authenticator is accepted, including software ones and passkeys synced
    through a cloud account. A synced passkey is only as safe as that cloud
    account.
  - **User verification is reported by the authenticator.** The server can't
    tell a real PIN check from a lying authenticator.
  - **The counter check catches clones only on authenticators that keep a
    counter.** Most synced passkeys always report 0.
- **Changing `WEBAUTHN_RP_ID` breaks every passkey.** Passkeys are bound to
  the RP ID they were made for. Users would need recovery codes to get back
  in and register new ones.
- **Lockout as denial of service.** Anyone who knows an email can trigger
  that account's 15-minute lockout, and keep re-triggering it. That's the
  inherent trade-off of per-account limits. The lockout is short, never
  permanent, and explained to the user. Allowlisting known devices would
  soften it and is not implemented.

## 4. Stolen or unlocked device

**Mitigations**

- **Nothing secret is persisted.** The web vault keeps the token, vault key
  and decrypted items in memory only; a reload locks it. The extension keeps
  them in service-worker memory and `chrome.storage.session`, which Chrome
  holds in memory and wipes when the browser closes (tested: relaunching the
  browser leaves the vault locked).
- **Auto-lock:**
  - Web: 5 minutes of inactivity by default. It uses the wall clock, so it
    also locks after a laptop wakes from sleep.
  - Extension: 15 minutes without using it, and immediately when the OS
    screen locks.
  - Locking zeroes the vault key, drops the session token, and discards
    decrypted items (web: unmounts the vault view; extension: clears the
    cache and session storage).
- **Locking and logging out end the server session** (`POST /logout`), so a
  token copied from memory stops working. The Security page lists every
  session with its client, browser and last use, and can end one or all of
  them.
- **Copied passwords are cleared from the clipboard** after 30 seconds, and
  at once when the vault locks. In the extension the background worker does
  it (the popup is usually closed by then).
- **Unlocking requires the master password** and runs the full login again.

**Not solved**

- **An unlocked device is fully exposed.** Anyone at an unlocked session can
  read every item until auto-lock.
- **JavaScript can't guarantee memory wiping.** Key byte arrays are zeroed,
  but strings (the typed master password, decrypted item text, JSON) can't
  be overwritten; they're released for garbage collection and may linger in
  memory, swap or crash dumps.
- **Malware, keyloggers and memory-scraping tools** on the device defeat all
  of this.
- **Ending a session is best effort.** If the device is offline when it
  locks, the server session stays valid until it expires (24 h). The token
  grants ciphertext only.
- **Clipboard clearing has limits.** Browsers don't let a page read the
  clipboard without a prompt, so the clear is unconditional: it can wipe
  something copied in another app in the meantime (the web vault skips the
  clear if you copy something else in the page). OS clipboard history or
  sync (Windows clipboard history, Universal Clipboard, clipboard managers)
  may keep their own copy. If the browser is closed within 30 seconds, the
  password stays on the clipboard.

## 5. Malicious browser extension environment

This covers other extensions installed in the same browser, and web pages
the extension interacts with.

**Mitigations (in our extension)**

- **Message authorization uses the browser-provided sender, not message
  contents.**
  - Only our popup can unlock, list items or change settings.
  - Content scripts can only ask about their own tab, identified by the URL
    the browser reports.
  - Messages from other extensions, subframes and web pages are rejected.
  - No `externally_connectable` entry, so web pages can't message us at all.
- **Secrets are out of reach of pages and content scripts.** The vault key
  lives in the service worker and `chrome.storage.session` (default
  `TRUSTED_CONTEXTS` access), which content scripts, other extensions and
  pages can't read. The content script bundle contains no crypto code, and
  the build fails if it does.
- **Credentials only go to their own domain, on request.** Autofill never
  happens without a trusted click (`event.isTrusted`), runs only in the top
  frame, only on https (or localhost), and only for items whose site matches
  the browser-reported hostname (exact host or subdomain). Lookalike domains
  get nothing.
- **The in-page UI is isolated.** Prompts render in a closed shadow root, and
  values are set through the isolated world's native setters, which page
  scripts can't override.
- **Popup and prompts never render with `innerHTML`**, so a malicious site
  name can't inject markup into an extension page.

**Not solved (explicitly)**

- **Another malicious or compromised extension with broad host
  permissions defeats the web vault and autofill.** Such an extension can
  inject scripts into the web vault's page:
  - to read the master password as it's typed
  - to read decrypted items from the DOM
  - to call the vault's own functions

  It can also read any password our extension fills into a page, and replace
  or overlay our prompts. The browser's extension model gives it the same
  access to page content that we have. **Nothing in this project can protect
  against it; users must trust every extension they install.**

- **The extension can't use passkeys.** WebAuthn from an extension popup is
  unreliable, and passkeys are bound to the web vault's origin. The
  extension keeps TOTP and recovery codes. For an account that is
  passkey-only (or has "Require passkey" on), it says so and points to the
  web vault, and the only way to unlock the extension itself is a recovery
  code. Each unlock uses one up, so such accounts will want the web vault
  for everyday use.
- **A compromised browser (or browser profile) is out of scope.**
  Everything, including our service worker, runs inside it.
- **XSS or a malicious page on the matching site.** Once a password is
  filled into a page's input, that page's scripts can read it. If
  `bank.example.com` has an XSS, filling there hands the attacker that one
  credential. The click requirement limits this to fills the user chose.
- **Fake forms and clickjacking on the matching site.** We can't tell a real
  login form from a lookalike the page injected, and a page can overlay our
  prompt to trick a click. Both are bounded to that site's own credential.
- **Phishing on lookalike domains.** Autofill refuses lookalikes, but the
  save prompt will offer to save a password the user typed into
  `examp1e.com` under that hostname, and the user can type a real password
  into any page.
- **Site matching has no public-suffix list.** Single-label suffixes (`com`)
  never match, but an item saved for `co.uk` would match every `*.co.uk`
  site.
- **Pending "save?" credentials** sit in `chrome.storage.session` for up to 2
  minutes, readable by anything that can read our service worker's
  storage (i.e. only a compromised browser).

## 6. Network attacker (MITM)

**Mitigations**

- **The master password, derived keys and vault key never cross the
  network**, so a passive attacker sees only the auth hash, ciphertext and
  session tokens.
- **TLS is expected everywhere, and the clients enforce it where they can:**
  - The extension refuses a non-https server URL (except localhost) and
    refuses autofill and save prompts on plain-http pages.
  - The web app talks only to its own origin (`connect-src 'self'`).
  - Docker Compose publishes the API on `127.0.0.1` only, for deployment
    behind a TLS proxy.
- **Captured ciphertext is useless** without the vault key, and tampering
  is detected by AEAD.

**Not solved**

- **The server doesn't enforce TLS itself** (no HTTPS listener, no HSTS).
  That depends on correct reverse-proxy configuration, and a deployment that
  exposes plain HTTP is vulnerable:
  - A passive attacker can capture the auth hash (a password-equivalent for
    login, though not for decryption) and session tokens. With those they can
    fetch ciphertext and run offline guessing (§3).
  - **An active attacker can modify the web app's JavaScript in transit and
    capture the master password**, the same failure as §1's malicious web app
    code. TLS is mandatory for the web vault.
- **No certificate pinning.** A mis-issued certificate or a TLS-intercepting
  proxy trusted by the device defeats TLS.

## 7. Ciphertext replay

Replaying or rearranging previously valid ciphertexts or credentials.

**Mitigations**

- **Every ciphertext is authenticated** (AEAD), so forged or modified bytes
  are rejected.
- **Domain separation via AAD:** a wrapped vault key can't be substituted for
  an item or vice versa, even under the same key.
- **Nonce reuse is prevented.** Nonces are 192-bit random and fresh per
  encryption. The server rejects duplicates globally, and rejects new content
  under an item's current nonce.
- **Credential replay is contained:**
  - Stored auth hashes and session tokens are hashed, so database values can't
    be replayed.
  - Sessions expire after 24 hours.
  - Login attempts are throttled.
  - Sessions can be ended from any other session, and a password change
    ends them all.
- **Items are bound to their id and revision.** Both are in each item's AAD,
  so the server can't **swap** two items' contents or relabel an old
  ciphertext as a **newer revision**: decryption fails, and the web vault
  reports the item as tampered with. The server accepts only the next
  revision, so revision numbers are never reused.
- **The vault manifest.** The client keeps an encrypted list of every item
  id and revision (bound to its own version number in the AAD), and every
  write moves it to the next version in the same transaction as the item
  change. Only a holder of the vault key can write one, so a client checking
  the items it's served against it catches, **on any device, even one that
  has never seen the vault**: hidden items, added or resurrected items, and
  items at another revision (rolled back). All are hidden and reported, in
  the web vault and the extension.
- **Rollback is also caught per device.** Each client remembers the highest
  manifest version and item revisions it has seen, so it also notices an
  older copy of the whole vault.
- **Password change rotates the vault key**, so an attacker who unwrapped
  the old vault key with a stolen password can't read anything saved
  afterwards, and can't forge new items.

**Not solved**

- **A whole older copy, on a fresh device.** A server can replay an entire
  earlier state (old manifest plus the matching old items) to a device with
  no history (a new device, cleared profile, or private window). It's
  internally consistent, so nothing can prove it's not the latest. The web
  vault shows when and from which app the vault last changed, so a person
  who changed it since can notice. Devices that have seen a newer version
  catch it.
- **Trust on first use for the first manifest.** Vaults from before the
  manifest existed get their first one from whichever client loads them
  first, based on what that client could verify. Items saved before
  revision binding (revision 0) use the old, unbound format until a client
  re-saves them (the web vault does so on load).
- **Auth-hash replay.** A captured auth hash (from an unencrypted connection
  or a compromised client) works as a login credential until the password
  is changed. It still doesn't decrypt anything.
- **Session-token replay** works until the token expires or the session is
  ended (log out, lock, "sign out everywhere", or a password change).

---

## Out of scope for v1

- Compromised operating systems, browsers, or hardware.
- Account recovery. A forgotten master password means the vault is
  unrecoverable, by design. The emergency kit (offered at signup and on the
  Security page) is a printable reminder of where the vault lives, with a
  blank for writing the password by hand; it never contains the password.
- Deleting an account removes it and every item from the database right
  away. Copies in the operator's backups are the operator's responsibility.
- **The breach check tells a third party something.** It never sends a
  password or a full hash, and the 5-character prefix matches roughly one in
  a million passwords, so a single request reveals nothing useful. But Have
  I Been Pwned (and anyone watching your network) learns that some browser
  at your address checked some number of passwords. That's why it's a button,
  not automatic.
- **Password history is more to lose.** Old passwords stay in the item's
  ciphertext (up to ten per login), so a compromised vault also exposes
  passwords you may still use elsewhere. Users can clear an item's history
  from its edit form.
- **Two-factor secrets kept with their passwords.** Storing a site's TOTP
  secret next to its password is convenient, but it means whoever gets into
  the vault (a guessed master password, an unlocked device) gets both
  factors at once. That's a real reduction from a separate authenticator
  app. Users who want the second factor to stay separate should leave the
  field empty for their most important accounts.
- **Files you import or export.** Other managers' CSV exports are plaintext:
  VaultX reads them locally and reminds you to delete them, but can't
  delete them for you. An exported backup is encrypted, but whoever gets
  the file can guess its password offline at Argon2id cost (like a stolen
  database), so the backup password needs the same "Strong" rating as a
  master password.
- Multi-user sharing, per-item keys, and mobile clients (see README →
  Future Work).
- Side channels in libsodium or the JavaScript runtime beyond using
  constant-time comparison for server-side secrets.
