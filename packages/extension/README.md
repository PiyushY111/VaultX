# @password-manager/extension

Manifest V3 browser extension (Chrome first). Unlocks the same vault as the
web app, offers to autofill matching logins, and offers to save new ones.
You can also add a login from the popup (**Add login**: the site is prefilled
from the current tab, with a password generator).
All cryptography runs in the background service worker via
`@password-manager/crypto`; the server only sees the auth hash and ciphertext.

## Build and load

```sh
npm run build -w @password-manager/extension    # outputs packages/extension/dist
```

1. Open `chrome://extensions`, turn on **Developer mode**.
2. **Load unpacked** → select `packages/extension/dist`.
3. Pin the extension, open it, click **Settings**, set the server URL
   (e.g. `http://127.0.0.1:3000`), and unlock with an account created in the
   web vault.

After rebuilding, click the reload icon on the extension's card.

## Architecture

| Part             | Runs in                      | Can see                                                           |
| ---------------- | ---------------------------- | ----------------------------------------------------------------- |
| `src/background` | Service worker               | Vault key, session token, decrypted items; all API calls          |
| `src/popup`      | Extension page               | Decrypted items (to list them), via messages to the background    |
| `src/content`    | Every https page (top frame) | Usernames of matching items; one credential after a click on Fill |
| `src/offscreen`  | Offscreen document (briefly) | Nothing: it only overwrites the clipboard with an empty string    |

- **Vault key storage:** memory plus `chrome.storage.session` (memory-only,
  cleared on browser close, not readable by content scripts), so the vault
  survives MV3 service-worker restarts. Nothing secret is in
  `chrome.storage.local` (it holds settings, the last email, and the revision
  ledger: item ids and revision numbers).
- **Locking:** after 15 minutes without using the extension (configurable:
  5/15/30/60), when the OS screen locks, when the server rejects the session,
  on browser restart, or on demand. Locking also ends the server session.
- **Clipboard:** a password copied from the popup is cleared after 30 seconds,
  or when the vault locks. The popup is usually closed by then, so the
  background schedules it with `chrome.alarms` and opens an offscreen
  document to write the clipboard (permissions: `offscreen`,
  `clipboardWrite`; neither shows an install warning).
- **Keyboard shortcut** (`src/background/commands.ts`): Ctrl+Shift+L (⌘⇧L on
  macOS) fills the login for the page: at once with one match, through our
  chooser with several, and a notice with none. When locked it opens the
  popup (Chrome 127+) or says so on the page. Ctrl+Shift+Y (⌘⇧Y) opens the
  popup. Chrome won't assign a shortcut another extension already uses;
  change either in `chrome://extensions/shortcuts` (Settings links there and
  shows the current one).
- **Right-click menu** on editable fields (permission `contextMenus`, no
  install warning): Fill login, Fill two-factor code, Fill card, Fill
  address, and Generate password. Top frame only: in an embedded frame it
  says it can't fill there. **Generate password** works while locked: it
  fills the right-clicked field and any other empty password field in its
  form (a sign-up form's "confirm password"), and the popup keeps it for 15
  minutes under "Generated password" (Show, Copy, Save as login), in case
  the site never offers to save it.
- **Site matching** (`src/background/matching.ts`, background only): by
  host, `www.` ignored, per each login's "Fill on" setting from the web
  vault: this site and its subdomains (the default), anywhere on the site's
  domain, this exact address only, or never. The Public Suffix List
  (`tldts`, pinned, with private suffixes such as `github.io`) means a login
  saved for a shared suffix like `co.uk` matches nothing, and that
  `alice.github.io` and `bob.github.io` are different sites. The list is
  frozen at build time; dependency updates refresh it. It's about 130 KB,
  so it stays out of the content script (`build.mjs` caps that at 50 KB).
- **Two-factor:** if the account has it on, the popup asks for the code after
  the password. The derived keys wait in the background worker's memory
  (never storage) for up to five minutes.
- **Baseline and checkpoint:** like the web vault, a vault with no
  trustworthy manifest is read-only until you confirm it, and only the popup
  can confirm it (content scripts can't, so a page can't). The popup's
  "Vault checkpoint" section shows the checkpoint and verifies one from
  another device.
- **No passkeys:** WebAuthn from an extension popup doesn't work reliably,
  and passkeys are bound to the web vault's origin. The extension accepts
  TOTP and recovery codes only. For an account that needs a passkey
  (passkeys and no authenticator app, or "Require passkey" on), the popup
  says so and points to the web vault. It still takes a recovery code, but
  each one works once, so such accounts are better off unlocking in the web
  vault.
- **Cards and identities:** on a checkout or address form (detected by
  `autocomplete` tokens, else field names and labels; `src/content/detectForms.ts`),
  the content script offers saved cards or identities, by label only, and
  fills one after a click. They aren't tied to a site, so any https page with
  such a form gets the offer (see THREAT_MODEL.md §5). The popup lists them,
  with "Fill in this tab" and, for cards, copying the number or security code
  (cleared from the clipboard after 30 seconds). Card fields inside a payment
  provider's iframe (Stripe, Braintree, Adyen…) can't be filled: the content
  script runs in the top frame only. On such pages the name on the card is
  still offered.
- **Notes** from the web vault are read and preserved (e.g. when a save
  prompt updates a login's password, its history is kept) but never listed
  or filled.
- **The trash:** logins in the web vault's trash are never listed, matched or
  filled either, and don't count as saved, so logging in with one offers to
  save it as a new login. The extension never deletes anything itself;
  emptying the trash happens in the web vault.
- **Two-factor codes:** the popup shows a login's live code (computed in the
  background; the secret never reaches the popup). On a site's 2FA page
  (`findOtpTarget` in `src/content/detect.ts`, with no password field
  present) the content script offers to fill the code for a matching login,
  after a click, like passwords. It finds either one field for the whole code
  (`autocomplete="one-time-code"`, or a short field named or labelled like a
  code) or a row of 4–8 one-digit boxes that something nearby names as a
  code (an attribute, the container's label, or a heading), so a PIN pad
  isn't mistaken for one. Split boxes get one digit each; if the page's
  widget rejects that, the code is pasted into the first box instead, and if
  that fails too, the prompt shows the code to type by hand.
- **Integrity checks:** the vault is checked against its encrypted manifest
  like the web vault's, and every write sends the next manifest. The popup
  warns about anything hidden, added, rolled back, or undecryptable.
- **Authorization:** the background checks every message's browser-provided
  sender. Only the popup can unlock or list items; content scripts can only ask
  about their own tab's URL. See the trust-boundary comment at the top of
  `src/content/index.ts`.

## Tests

```sh
npm test -w @password-manager/extension                                   # unit tests
API_URL=http://127.0.0.1:3000 npm run test:e2e -w @password-manager/extension  # Chromium + real API
```

The end-to-end tests load `dist/` into Playwright's Chromium (branded Chrome no
longer accepts `--load-extension`) and need the API running (`docker compose up`).
If Chromium isn't installed yet: `npx playwright install chromium`.

Playwright can't press extension shortcuts or click context-menu entries, so
`test/commands.test.ts` covers that logic, and these are checked by hand
before a release (load `dist/` unpacked, unlock, use a site with one saved
login and one with two):

1. Ctrl/⌘+Shift+L on a login page with one match fills it; with two, the
   chooser appears (even after "Not now"); with none, "No saved login for
   this site"; locked, the popup opens.
2. Right-click a field → VaultX → each entry does the same for logins, 2FA
   codes, cards and addresses; inside an iframe, the "can't fill inside
   embedded frames" notice appears.
3. Generate password on a sign-up form fills the password and its
   confirmation; the popup shows it under "Generated password"; "Save as
   login" opens the form filled in; locking forgets it.
4. Settings shows the current shortcut; "Change" opens
   `chrome://extensions/shortcuts`.
