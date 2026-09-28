/*
 * ============================================================================
 * TRUST BOUNDARY: the content script trusts the page's DOM.
 * ============================================================================
 *
 * This script runs inside arbitrary web pages. The DOM it inspects — which
 * inputs exist, what they're called, what they contain — is fully controlled
 * by the page, including any attacker-controlled script on it (XSS, a
 * malicious ad, a compromised third-party library). So:
 *
 * What this DOES protect against
 * - Cross-site credential theft. The background decides which items match
 *   using the browser-reported URL of the sending frame (`sender.url`), not
 *   anything this script or the page says. evil.com only ever receives
 *   evil.com's saved logins, however it dresses up its forms.
 * - Silent autofill. Nothing is filled until the user clicks "Fill" in our
 *   prompt (or in the popup). Clicks with `isTrusted === false` (dispatched
 *   by page scripts) are ignored.
 * - Page scripts driving the extension. This script runs in an isolated world:
 *   page JS can't call chrome.runtime, read our variables, or replace the
 *   native value setter we use. The prompt lives in a closed shadow root.
 * - Hidden iframes. The script runs in the top frame only (`all_frames: false`
 *   and the check below), and the background rejects messages from subframes.
 * - Insecure pages. No autofill or save prompts on plain-http pages (except
 *   localhost), so credentials aren't handed to a network attacker.
 * - Vault access from the page. The vault key and the item list never enter
 *   this script. It sees usernames of matching items and, only after a click,
 *   one matching credential.
 *
 * What this does NOT protect against
 * - A malicious or compromised page on the *matching* site. Once we fill a
 *   password into the page's input, page script can read it. If
 *   bank.example.com has an XSS, filling there gives the attacker that one
 *   credential. That's inherent to autofill; requiring a click limits it to
 *   deliberate fills.
 * - Fake forms on the matching site. We fill wherever the page puts a
 *   password field; we can't tell a real login form from a lookalike the page
 *   injected.
 * - Clickjacking. A page can overlay or disguise our prompt to trick a click.
 *   The prompt only fills the credential for the page's own domain, which
 *   bounds the damage to the previous point.
 * - Save-prompt spoofing and spam. A page can fake a "submission" to trigger
 *   a save offer, or feed us wrong values. Saving always needs a click and
 *   only stores what the page submitted, under the page's own hostname.
 * - Lookalike domains (examp1e.com). Matching is exact host or subdomain, so
 *   they get nothing, but the save prompt will happily save a phished
 *   password under the lookalike's hostname.
 * - A compromised browser, OS, or another malicious extension with broad
 *   permissions. Those sit below this trust boundary.
 * ============================================================================
 */

import type {
  ContentRequest,
  FillCredentialMessage,
  ItemSummary,
  PendingSavePrompt,
  Response,
  TotpCodeResponse,
  VaultUnlockedMessage,
} from '../shared/messages';
import { securePageHost } from '../shared/urls';
import {
  fillLogin,
  findLoginFields,
  findOtpField,
  readSubmittedCredential,
  setFieldValue,
} from './detect';
import { Prompt } from './ui';

const SCAN_DEBOUNCE_MS = 400;
const PENDING_CHECK_DELAY_MS = 800;

async function send<T>(request: ContentRequest): Promise<Response<T>> {
  try {
    return (await chrome.runtime.sendMessage(request)) as Response<T>;
  } catch {
    return { ok: false, error: 'Extension unavailable' };
  }
}

function main(): void {
  if (window.top !== window) return;
  // Mirrors the background's rule; the background enforces it regardless.
  if (!securePageHost(location.href)) return;

  const prompt = new Prompt();
  let offeredFill = false;
  let offeredTotp = false;
  let showedLocked = false;
  let dismissed = false;
  let savePromptShown = false;
  let lastCapture = '';

  function fillFirstForm(username: string, password: string): boolean {
    const fields = findLoginFields(document)[0];
    if (!fields) return false;
    fillLogin(fields, username, password);
    return true;
  }

  async function offerFill(): Promise<void> {
    if (offeredFill || dismissed || savePromptShown) return;
    if (findLoginFields(document).length === 0) return offerTotp();
    offeredFill = true;
    const response = await send<ItemSummary[]>({ type: 'getMatches' });
    if (!response.ok) {
      if (response.locked) {
        showedLocked = true;
        prompt.show({
          message: 'VaultX is locked',
          detail: 'Click the extension icon and unlock to fill this login.',
          actions: [{ label: 'Dismiss', onClick: dismiss }],
        });
      }
      return;
    }
    const matches = response.data;
    if (matches.length === 0) return;
    prompt.show({
      message:
        matches.length === 1 ? 'Fill saved login?' : `${matches.length} saved logins for this site`,
      detail: matches.length === 1 ? matches[0]!.username || '(no username)' : location.hostname,
      choices: matches.map((match) => ({
        value: match.id,
        label: match.username || '(no username)',
      })),
      actions: [
        { label: 'Not now', onClick: dismiss },
        {
          label: 'Fill',
          primary: true,
          onClick: () => void fill(prompt.selection ?? matches[0]!.id),
        },
      ],
    });
  }

  async function fill(itemId: string): Promise<void> {
    const response = await send<{ username: string; password: string }>({ type: 'fill', itemId });
    if (!response.ok) {
      prompt.show({
        message: 'Could not fill',
        detail: response.error,
        actions: [{ label: 'Close', onClick: dismiss }],
      });
      return;
    }
    fillFirstForm(response.data.username, response.data.password);
    prompt.hide();
  }

  /** A two-factor step: offer the saved code for this site, if there is one. */
  async function offerTotp(): Promise<void> {
    if (offeredTotp || !findOtpField(document)) return;
    offeredTotp = true;
    const response = await send<ItemSummary[]>({ type: 'getTotpMatches' });
    if (!response.ok || response.data.length === 0) return;
    const matches = response.data;
    prompt.show({
      message: 'Fill two-factor code?',
      detail: matches.length === 1 ? matches[0]!.username || location.hostname : location.hostname,
      choices: matches.map((match) => ({
        value: match.id,
        label: match.username || '(no username)',
      })),
      actions: [
        { label: 'Not now', onClick: dismiss },
        {
          label: 'Fill code',
          primary: true,
          onClick: () => void fillTotp(prompt.selection ?? matches[0]!.id),
        },
      ],
    });
  }

  async function fillTotp(itemId: string): Promise<void> {
    const field = findOtpField(document);
    const response = await send<TotpCodeResponse>({ type: 'fillTotp', itemId });
    if (!response.ok || !field) {
      prompt.show({
        message: 'Could not fill the code',
        detail: response.ok ? 'The code field is gone.' : response.error,
        actions: [{ label: 'Close', onClick: dismiss }],
      });
      return;
    }
    setFieldValue(field, response.data.code);
    prompt.hide();
  }

  function dismiss(): void {
    dismissed = true;
    prompt.hide();
  }

  // --- Save prompt -----------------------------------------------------------

  function capture(scope: ParentNode): void {
    const credential = readSubmittedCredential(scope);
    if (!credential) return;
    // Avoid re-sending the same pair when submit, click and Enter all fire.
    const fingerprint = `${credential.username}\u0000${credential.password}`;
    if (fingerprint === lastCapture) return;
    lastCapture = fingerprint;
    void send({ type: 'captureCredential', ...credential }).then(() => {
      // For single-page apps that don't navigate after login.
      setTimeout(() => void checkPendingSave(), PENDING_CHECK_DELAY_MS);
    });
  }

  async function checkPendingSave(): Promise<void> {
    const response = await send<PendingSavePrompt | null>({ type: 'getPendingSave' });
    if (!response.ok || !response.data) return;
    const pending = response.data;
    savePromptShown = true;
    prompt.show({
      message: pending.kind === 'update' ? 'Update saved password?' : 'Save this password?',
      detail: `${pending.username || '(no username)'} on ${pending.host}`,
      actions: [
        { label: 'Not now', onClick: () => void resolvePending(false) },
        {
          label: pending.kind === 'update' ? 'Update' : 'Save',
          primary: true,
          onClick: () => void resolvePending(true),
        },
      ],
    });
  }

  async function resolvePending(save: boolean): Promise<void> {
    const response = await send({ type: 'resolvePendingSave', save });
    savePromptShown = false;
    if (save && !response.ok) {
      prompt.show({
        message: 'Could not save',
        detail: response.error,
        actions: [{ label: 'Close', onClick: dismiss }],
      });
      return;
    }
    prompt.hide();
  }

  document.addEventListener(
    'submit',
    (event) => {
      if (event.target instanceof HTMLFormElement) capture(event.target);
    },
    true,
  );
  // Many sites log in via a button click or Enter key without a real form submit.
  document.addEventListener(
    'click',
    (event) => {
      const button = (event.target as Element | null)?.closest?.(
        'button, input[type="submit"], [role="button"]',
      );
      if (button) capture((button as HTMLElement).closest('form') ?? document);
    },
    true,
  );
  document.addEventListener(
    'keydown',
    (event) => {
      if (event.key === 'Enter' && event.target instanceof HTMLInputElement)
        capture(event.target.form ?? document);
    },
    true,
  );

  // Fill requested from the popup. The background already checked the item
  // matches this tab's URL; re-check our own hostname in case the tab
  // navigated between that check and this message arriving.
  chrome.runtime.onMessage.addListener(
    (message: (FillCredentialMessage & { host?: string }) | VaultUnlockedMessage, sender) => {
      if (sender.id !== chrome.runtime.id) return;
      if (message?.type === 'vaultUnlocked') {
        // Replace the "locked" notice with a real offer.
        if (showedLocked && !dismissed) {
          showedLocked = false;
          offeredFill = false;
          prompt.hide();
          void offerFill();
        }
        return;
      }
      if (message?.type !== 'fillCredential' || securePageHost(location.href) !== message.host)
        return;
      fillFirstForm(message.username, message.password);
      prompt.hide();
    },
  );

  // Login forms often render late (single-page apps), so rescan on DOM changes.
  let scanTimer: number | undefined;
  new MutationObserver(() => {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(() => void offerFill(), SCAN_DEBOUNCE_MS);
  }).observe(document.documentElement, { childList: true, subtree: true });

  void checkPendingSave().then(() => offerFill());
}

main();
