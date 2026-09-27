# @password-manager/extension

Manifest V3 browser extension (Chrome first). Unlocks the same vault as the
web app, offers to autofill matching logins, and offers to save new ones.
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

- **Vault key storage:** memory plus `chrome.storage.session` (memory-only,
  cleared on browser close, not readable by content scripts), so the vault
  survives MV3 service-worker restarts. Nothing secret is in
  `chrome.storage.local`.
- **Locking:** after 15 minutes without using the extension (configurable:
  5/15/30/60), when the OS screen locks, when the server rejects the session,
  on browser restart, or on demand.
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
