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
- **Logins only:** notes, cards and identities from the web vault are read
  and preserved (e.g. when a save prompt updates a login's password, its
  history is kept) but never listed, matched or filled.
- **Two-factor codes:** the popup shows a login's live code (computed in the
  background; the secret never reaches the popup). On a site's 2FA page
  (`findOtpField` in `src/content/detect.ts`: an `autocomplete="one-time-code"`
  field, or a short field named/labelled like a code, with no password field
  present) the content script offers to fill the code for a matching login,
  after a click, like passwords. Sites that split the code into one box per
  digit aren't recognized.
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
