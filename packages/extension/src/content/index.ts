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
 *   prompt (or in the popup), presses the extension's keyboard shortcut, or
 *   picks an entry in its right-click menu. Clicks with `isTrusted === false`
 *   (dispatched by page scripts) are ignored, and a page can neither press
 *   an extension shortcut nor click its menu: those are browser UI, so with
 *   a single match the shortcut fills without a second click.
 * - Page scripts driving the extension. This script runs in an isolated world:
 *   page JS can't call chrome.runtime, read our variables, or replace the
 *   native value setter we use. The prompt lives in a closed shadow root.
 * - Hidden iframes. The script runs in the top frame only (`all_frames: false`
 *   and the check below), and the background rejects messages from subframes.
 * - Insecure pages. No autofill or save prompts on plain-http pages (except
 *   localhost), so credentials aren't handed to a network attacker.
 * - Vault access from the page. The vault key and the item list never enter
 *   this script. It sees usernames of matching items and, only after a click,
 *   one matching credential. For cards and identities it sees labels only
 *   ("Visa •••• 4242 · Jane D.", "Home · Jane"), and one item's fields after
 *   a click.
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
 * - Lookalike domains (examp1e.com). Matching is by host (see the
 *   background's matching.ts), so they get nothing, but the save prompt
 *   will happily save a phished password under the lookalike's hostname.
 *   A login saved for a public suffix (co.uk, github.io) matches no page.
 * - Cards and identities on any page. They aren't tied to a site, so every
 *   secure page with a checkout or address form gets an offer, and a click
 *   there hands that page the item. A phishing checkout gets the card if the
 *   user clicks Fill. Domain matching can't help here; the click (every time,
 *   never on load) and the labels-only offer are what's left. Card fields in
 *   a payment provider's iframe (Stripe, Braintree…) aren't filled: this
 *   script runs in the top frame only.
 * - A compromised browser, OS, or another malicious extension with broad
 *   permissions. Those sit below this trust boundary.
 * ============================================================================
 */

import type {
  BackgroundToContent,
  ContentRequest,
  ItemSummary,
  PendingSavePrompt,
  Response,
  TotpCodeResponse,
} from '../shared/messages';
import { securePageHost } from '../shared/urls';
import {
  fillGeneratedPassword,
  fillLogin,
  fillOtp,
  findLoginFields,
  findOtpTarget,
  readSubmittedCredential,
  setFieldValue,
  type OtpTarget,
} from './detect';
import { createFormOffers } from './offers';
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

/** The code field, or the first box of a split code. */
const otpAnchor = (target: OtpTarget | null) =>
  target?.kind === 'single' ? target.input : (target?.inputs[0] ?? null);

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
  /** The field the user last right-clicked: where the menu's "Generate password" goes. */
  let rightClicked: HTMLInputElement | null = null;

  function showNotice(message: string, detail?: string): void {
    prompt.show({
      message,
      ...(detail && { detail }),
      actions: [{ label: 'Close', onClick: () => prompt.hide() }],
    });
  }

  function fillFirstForm(username: string, password: string): boolean {
    const fields = findLoginFields(document)[0];
    if (!fields) return false;
    fillLogin(fields, username, password);
    return true;
  }

  /** `force`: the user asked (shortcut or menu), so offer even after "Not now". */
  async function offerFill(force = false): Promise<void> {
    if (!force && (offeredFill || dismissed || savePromptShown)) return;
    if (findLoginFields(document).length === 0) {
      return force ? showNotice('There’s no login form on this page') : offerOtherForms();
    }
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
    const fields = findLoginFields(document)[0];
    const targetField = fields ? (fields.username ?? fields.password) : null;
    prompt.show(
      {
        message:
          matches.length === 1
            ? 'Fill saved login?'
            : `${matches.length} saved logins for this site`,
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
      },
      targetField,
    );
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

  const formOffers = createFormOffers({ prompt, send, dismiss: () => dismiss() });

  /** No login form: a checkout or address form, else a two-factor step. */
  async function offerOtherForms(): Promise<void> {
    if (await formOffers.offer()) return;
    return offerTotp();
  }

  /** A two-factor step: offer the saved code for this site, if there is one. */
  async function offerTotp(force = false): Promise<void> {
    if (!findOtpTarget(document)) {
      if (force) showNotice('There’s no two-factor code field on this page');
      return;
    }
    if (offeredTotp && !force) return;
    offeredTotp = true;
    const response = await send<ItemSummary[]>({ type: 'getTotpMatches' });
    if (!response.ok || response.data.length === 0) return;
    const matches = response.data;
    prompt.show(
      {
        message: 'Fill two-factor code?',
        detail:
          matches.length === 1 ? matches[0]!.username || location.hostname : location.hostname,
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
      },
      otpAnchor(findOtpTarget(document)),
    );
  }

  async function fillTotp(itemId: string): Promise<void> {
    const response = await send<TotpCodeResponse>({ type: 'fillTotp', itemId });
    // Found again now: the page may have re-rendered while we asked.
    const target = findOtpTarget(document);
    if (!response.ok || !target) {
      prompt.show({
        message: 'Could not fill the code',
        detail: response.ok ? 'The code field is gone.' : response.error,
        actions: [{ label: 'Close', onClick: dismiss }],
      });
      return;
    }
    const { code, secondsLeft } = response.data;
    if (fillOtp(target, code)) {
      prompt.hide();
      return;
    }
    // A widget we couldn't type into: show the code (to the user, in our
    // closed prompt, not to the page) so it can be typed by hand.
    prompt.show(
      {
        message: 'Type this code',
        detail: `${code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2')} · valid for ${secondsLeft} more seconds`,
        actions: [{ label: 'Close', onClick: dismiss }],
      },
      otpAnchor(target),
    );
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
  // Messages from our background (the popup's "Fill", the shortcut, the
  // right-click menu). The background already checked the item against this
  // tab's URL; anything carrying a value is re-checked against our own host,
  // in case the tab navigated between that check and this message.
  chrome.runtime.onMessage.addListener((message: BackgroundToContent, sender) => {
    if (sender.id !== chrome.runtime.id) return;
    const forThisPage = 'host' in message && securePageHost(location.href) === message.host;
    switch (message?.type) {
      case 'vaultUnlocked':
        // Replace the "locked" notice with a real offer.
        if (showedLocked && !dismissed) {
          showedLocked = false;
          offeredFill = false;
          prompt.hide();
          void offerFill();
        }
        return;
      case 'showChooser':
        if (message.kind === 'login') void offerFill(true);
        else if (message.kind === 'totp') void offerTotp(true);
        else void formOffers.offerKind(message.kind);
        return;
      case 'showNotice':
        showNotice(message.message, message.detail);
        return;
      case 'fillCredential':
        if (!forThisPage) return;
        if (fillFirstForm(message.username, message.password)) prompt.hide();
        else showNotice('There’s no login form on this page');
        return;
      case 'fillForm':
        if (forThisPage) formOffers.fillFromPopup(message);
        return;
      case 'fillTotpCode':
        if (forThisPage) fillTotpCode(message.code);
        return;
      case 'fillGenerated':
        if (!forThisPage) return;
        if (fillGeneratedPassword(rightClicked, document, message.password) > 0) prompt.hide();
        else
          showNotice(
            'No password field to fill',
            'Right-click the password field and try again. The password is kept in the VaultX popup for 15 minutes.',
          );
        return;
    }
  });

  // Remembered for the menu's "Generate password". Capture phase, before the page sees it.
  document.addEventListener(
    'contextmenu',
    (event) => {
      rightClicked = event.target instanceof HTMLInputElement ? event.target : null;
    },
    true,
  );

  /** A code from the menu: into the code field, else the right-clicked field, else shown. */
  function fillTotpCode(code: string): void {
    const target = findOtpTarget(document);
    if (target && fillOtp(target, code)) return prompt.hide();
    if (!target && rightClicked) {
      setFieldValue(rightClicked, code);
      return prompt.hide();
    }
    showNotice('Type this code', code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2'));
  }

  // Login forms often render late (single-page apps), so rescan on DOM changes.
  let scanTimer: number | undefined;
  new MutationObserver(() => {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(() => void offerFill(), SCAN_DEBOUNCE_MS);
  }).observe(document.documentElement, { childList: true, subtree: true });

  void checkPendingSave().then(() => offerFill());
}

main();
