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
  The web vault reports undecryptable items as possibly tampered with; the
  extension skips them (it doesn't yet surface a warning).
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
  delete or withhold items, refuse writes, or serve an old copy of the vault
  to a device that hasn't seen a newer one (see §7). Swapping items or
  passing off old ciphertexts as current is detected.
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

**Not solved**

- **Offline guessing of weak master passwords**, as in §1. The breach gives
  the attacker unlimited offline attempts; throttling doesn't apply.
- **Metadata exposure**, as in §1.
- **Backups and logs** are the operator's responsibility. The API doesn't
  log request bodies or `Authorization` headers.

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
- **No second factor.** A captured auth hash, or a guessed password, is
  enough to log in. (A second factor would protect server access to the
  ciphertext, not the offline attack.)
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
- **Rollback is caught on devices that have seen the item.** Each client
  remembers the highest revision it has seen per item (and which items it
  deleted). An item served at an older revision, or a deleted item that
  reappears, is hidden and reported as rolled back.
- **Password change rotates the vault key**, so an attacker who unwrapped
  the old vault key with a stolen password can't read anything saved
  afterwards, and can't forge new items.

**Not solved**

- **Rollback on a device that has never seen the vault.** The revision
  ledger lives in each browser. A new device, a cleared browser profile, or
  a private window has no ledger, so the server can serve it an old but
  genuine revision of any item, or a whole stale copy of the vault, without
  it noticing. A signed, client-verifiable vault manifest would close this;
  it isn't implemented.
- **Withholding items.** The server can hide items (or refuse writes).
  Clients can't tell an item the server withholds from one deleted on
  another device. A deleted item that reappears is caught by the ledger on
  devices that saw it deleted.
- **Legacy items (revision 0)** from before binding use the old, unbound
  format until a client re-saves them. The web vault does so on load; until
  then, or on a device without a ledger, they can be swapped or rolled back
  as before.
- **Auth-hash replay.** A captured auth hash (from an unencrypted connection
  or a compromised client) works as a login credential until the password
  is changed. It still doesn't decrypt anything.
- **Session-token replay** works until the token expires or the session is
  ended (log out, lock, "sign out everywhere", or a password change).

---

## Out of scope for v1

- Compromised operating systems, browsers, or hardware.
- Account recovery. A forgotten master password means the vault is
  unrecoverable, by design.
- Multi-user sharing, per-item keys, and mobile clients (see README →
  Future Work).
- Side channels in libsodium or the JavaScript runtime beyond using
  constant-time comparison for server-side secrets.
