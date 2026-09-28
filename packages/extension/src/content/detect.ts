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

const isUsable = (input: HTMLInputElement): boolean =>
  !input.disabled && !input.readOnly && isVisible(input);

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
const words = (text: string) => text.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ');

/**
 * The field on a two-factor step that wants a 6–8 digit code, if the page
 * has one and no password field (that's a login form instead). Sites that
 * split the code into one box per digit aren't recognized.
 */
export function findOtpField(doc: Document): HTMLInputElement | null {
  if (findLoginFields(doc).length > 0) return null;
  const inputs = [
    ...doc.querySelectorAll<HTMLInputElement>(
      'input:not([type]), input[type="text"], input[type="tel"], input[type="number"]',
    ),
  ].filter(isUsable);
  const byAutocomplete = inputs.find((input) => input.autocomplete === 'one-time-code');
  if (byAutocomplete) return byAutocomplete;
  return (
    inputs.find((input) => {
      const described = [
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute('aria-label') ?? '',
        input.labels?.[0]?.textContent ?? '',
      ].join(' ');
      const maxLength = input.maxLength;
      const codeSized = maxLength === -1 || (maxLength >= 6 && maxLength <= 8);
      return codeSized && OTP_HINT.test(words(described));
    }) ?? null
  );
}
