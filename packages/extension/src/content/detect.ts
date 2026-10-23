/**
 * Login-form detection and filling. Pure DOM helpers, no extension APIs, so
 * they can be tested in jsdom.
 */

export interface LoginFields {
  form: HTMLFormElement | null;
  username: HTMLInputElement | null;
  password: HTMLInputElement;
}

const USERNAME_INPUT_TYPES = new Set(['text', 'email', 'tel']);

export function isVisible(element: Element): boolean {
  if (element instanceof HTMLInputElement && element.type === 'hidden') return false;
  for (let node: Element | null = element; node; node = node.parentElement) {
    if (node.hasAttribute('hidden') || node.getAttribute('aria-hidden') === 'true') return false;
    const style = node.ownerDocument.defaultView?.getComputedStyle(node);
    if (style && (style.display === 'none' || style.visibility === 'hidden')) return false;
  }
  return true;
}

export const isUsable = (input: HTMLInputElement | HTMLSelectElement): boolean =>
  !input.disabled && !(input instanceof HTMLInputElement && input.readOnly) && isVisible(input);

/** The field most likely to hold the username for a given password field. */
export function findUsernameField(password: HTMLInputElement): HTMLInputElement | null {
  const scope: ParentNode = password.form ?? password.ownerDocument;
  const candidates = [...scope.querySelectorAll('input')].filter(
    (input) => USERNAME_INPUT_TYPES.has(input.type) && isUsable(input),
  );
  const labelled = candidates.find((input) => /\b(username|email)\b/i.test(input.autocomplete));
  if (labelled) return labelled;
  // Otherwise the nearest candidate before the password field.
  const before = candidates.filter(
    (input) => input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING,
  );
  return before.at(-1) ?? null;
}

/** Visible login forms: the first usable password field per form (or per page, for form-less logins). */
export function findLoginFields(doc: Document): LoginFields[] {
  const seen = new Set<HTMLFormElement | null>();
  const result: LoginFields[] = [];
  for (const password of doc.querySelectorAll<HTMLInputElement>('input[type="password"]')) {
    if (!isUsable(password) || seen.has(password.form)) continue;
    seen.add(password.form);
    result.push({ form: password.form, username: findUsernameField(password), password });
  }
  return result;
}

/**
 * Sets a value the way a user would, so frameworks (React, Vue, ...) that
 * track input via events see it. Uses the native setter from this (isolated)
 * world, which page scripts cannot override.
 */
export function setFieldValue(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

const isEmptyPasswordField = (input: HTMLInputElement) =>
  input.type === 'password' && !input.value && isUsable(input);

/**
 * Fills a generated password into `target` (the right-clicked field), and
 * into the other empty password fields of its form, a sign-up form's
 * "confirm password". Without a usable target, starts from the page's first
 * empty password field. Returns how many fields it filled.
 */
export function fillGeneratedPassword(
  target: HTMLInputElement | null,
  doc: Document,
  password: string,
): number {
  const firstEmpty = () =>
    [...doc.querySelectorAll<HTMLInputElement>('input[type="password"]')].find(
      isEmptyPasswordField,
    ) ?? null;
  // A right-clicked field we can't use (hidden, disabled) means nothing to fill.
  const start = target ? (isUsable(target) ? target : null) : firstEmpty();
  if (!start) return 0;
  const scope: ParentNode = start.form ?? doc;
  const others = [...scope.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(
    (input) => input !== start && isEmptyPasswordField(input),
  );
  for (const input of [start, ...others]) setFieldValue(input, password);
  return 1 + others.length;
}

export function fillLogin(fields: LoginFields, username: string, password: string): void {
  if (fields.username && username) setFieldValue(fields.username, username);
  setFieldValue(fields.password, password);
}

/**
 * The username/password pair a form is about to submit. With several
 * filled password fields (sign-up or change-password forms) the last one is
 * the new password.
 */
export function readSubmittedCredential(
  scope: ParentNode,
): { username: string; password: string } | null {
  const passwords = [...scope.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(
    (input) => input.value && isVisible(input),
  );
  const password = passwords.at(-1);
  if (!password) return null;
  const username = findUsernameField(passwords[0]!)?.value.trim() ?? '';
  return { username, password: password.value };
}

const OTP_HINT =
  /\b(otp|totp|2fa|mfa|one ?time|verification code|auth(entication)? code|security code|two factor|mfa code)\b/i;

/** "totpCode", "otp_code" and "mfa-code" → "totp Code", "otp code", "mfa code", so \b matches. */
export const words = (text: string) =>
  text.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ');

const TEXT_INPUTS =
  'input:not([type]), input[type="text"], input[type="tel"], input[type="number"]';

/** Split codes come in 4 to 8 boxes; 6 is by far the most common. */
const MIN_SPLIT_BOXES = 4;
const MAX_SPLIT_BOXES = 8;
const USUAL_SPLIT_BOXES = 6;
/** How far up from the boxes to look for a heading or label that names the step. */
const HINT_ANCESTOR_LEVELS = 3;

export type OtpTarget =
  { kind: 'single'; input: HTMLInputElement } | { kind: 'split'; inputs: HTMLInputElement[] };

const describeInput = (input: HTMLInputElement) =>
  words(
    [
      input.name,
      input.id,
      input.placeholder,
      input.getAttribute('aria-label') ?? '',
      input.labels?.[0]?.textContent ?? '',
    ].join(' '),
  );

/** A box for one digit of a split code: one character wide, by its limit or its size. */
const isDigitBox = (input: HTMLInputElement) =>
  input.maxLength === 1 || input.getAttribute('size') === '1';

/** The field for a whole 6–8 digit code (not a box for one digit of it). */
function findSingleOtpField(inputs: HTMLInputElement[]): HTMLInputElement | null {
  const usable = inputs.filter((input) => isUsable(input) && !isDigitBox(input));
  const byAutocomplete = usable.find((input) => input.autocomplete === 'one-time-code');
  if (byAutocomplete) return byAutocomplete;
  return (
    usable.find((input) => {
      const maxLength = input.maxLength;
      const codeSized = maxLength === -1 || (maxLength >= 6 && maxLength <= 8);
      return codeSized && OTP_HINT.test(describeInput(input));
    }) ?? null
  );
}

/** Do two boxes sit together: the same parent, or each wrapped in its own element? */
const sideBySide = (a: Element, b: Element) =>
  a.parentElement === b.parentElement ||
  (a.parentElement?.parentElement ?? null) === (b.parentElement?.parentElement ?? null);

/**
 * Runs of usable digit boxes next to each other in document order. Any other
 * input in between, including a hidden or disabled box, ends a run.
 */
function digitBoxRuns(inputs: HTMLInputElement[]): HTMLInputElement[][] {
  const runs: HTMLInputElement[][] = [];
  let run: HTMLInputElement[] = [];
  for (const input of inputs) {
    const fits =
      isDigitBox(input) && isUsable(input) && (!run[0] || sideBySide(run.at(-1)!, input));
    if (fits) {
      run.push(input);
      continue;
    }
    if (run.length) runs.push(run);
    run = isDigitBox(input) && isUsable(input) ? [input] : [];
  }
  if (run.length) runs.push(run);
  return runs;
}

/** The closest element containing every box. */
function commonAncestor(boxes: HTMLInputElement[]): Element | null {
  let node: Element | null = boxes[0]!.parentElement;
  while (node && !boxes.every((box) => node!.contains(box))) node = node.parentElement;
  return node;
}

/**
 * Does something say these boxes want a code? Digit boxes alone could be a
 * PIN pad or card digits, so one of them, their container, or a heading or
 * label near them must name the step.
 */
function namesACode(boxes: HTMLInputElement[]): boolean {
  if (
    boxes.some((box) => box.autocomplete === 'one-time-code' || OTP_HINT.test(describeInput(box)))
  )
    return true;
  let node = commonAncestor(boxes);
  for (let level = 0; node && level <= HINT_ANCESTOR_LEVELS; level++, node = node.parentElement) {
    const nearby = [...node.querySelectorAll('h1, h2, h3, h4, legend, label')].map(
      (element) => element.textContent ?? '',
    );
    if (
      [node.getAttribute('aria-label') ?? '', ...nearby].some((text) => OTP_HINT.test(words(text)))
    )
      return true;
  }
  return false;
}

/**
 * Where a two-factor step wants its code: one field for the whole 6–8 digit
 * code, or a row of 4–8 boxes with one digit each. Null on a page with a
 * password field (that's a login form instead) or without a code field.
 */
export function findOtpTarget(doc: Document): OtpTarget | null {
  if (findLoginFields(doc).length > 0) return null;
  const inputs = [...doc.querySelectorAll<HTMLInputElement>(TEXT_INPUTS)];
  const single = findSingleOtpField(inputs);
  if (single) return { kind: 'single', input: single };
  const runs = digitBoxRuns(inputs).filter(
    (run) => run.length >= MIN_SPLIT_BOXES && run.length <= MAX_SPLIT_BOXES && namesACode(run),
  );
  const best = runs.find((run) => run.length === USUAL_SPLIT_BOXES) ?? runs[0];
  return best ? { kind: 'split', inputs: best } : null;
}

/** The field for a whole code, if the page has one (see {@link findOtpTarget}). */
export function findOtpField(doc: Document): HTMLInputElement | null {
  const target = findOtpTarget(doc);
  return target?.kind === 'single' ? target.input : null;
}

/** A paste of `text`, the way the browser sends one (for OTP widgets that only take a paste). */
function pasteEvent(text: string): Event {
  try {
    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', text);
    return new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true });
  } catch {
    // No DataTransfer constructor (e.g. jsdom): the same shape, by hand.
    const event = new Event('paste', { bubbles: true, cancelable: true });
    Object.defineProperty(event, 'clipboardData', {
      value: { getData: (type: string) => (type.startsWith('text') ? text : '') },
    });
    return event;
  }
}

const holds = (inputs: HTMLInputElement[], code: string) =>
  inputs.every((input, i) => input.value === code[i]);

/**
 * Fills a code into its target. For split boxes: one digit per box (with key
 * events, which some widgets move focus on); if the boxes don't end up
 * holding the code, a paste into the first box instead. False if the code
 * didn't go in (or doesn't fit the boxes), so the caller can show it instead.
 */
export function fillOtp(target: OtpTarget, code: string): boolean {
  if (target.kind === 'single') {
    setFieldValue(target.input, code);
    return true;
  }
  const { inputs } = target;
  if (code.length !== inputs.length) return false;
  inputs.forEach((input, i) => {
    const key = code[i]!;
    input.focus();
    input.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
    setFieldValue(input, key);
    input.dispatchEvent(new KeyboardEvent('keyup', { key, bubbles: true }));
  });
  if (holds(inputs, code)) return true;

  for (const input of inputs) setFieldValue(input, '');
  inputs[0]!.focus();
  inputs[0]!.dispatchEvent(pasteEvent(code));
  return holds(inputs, code);
}
