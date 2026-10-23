/**
 * Filling card and address forms found by detectForms.ts. Pure DOM helpers;
 * values are set with the native setters, like logins (see setFieldValue).
 */
import { setFieldValue } from './detect';
import type { CardKey, DetectedForm, FillableField, IdentityKey } from './detectForms';

export interface FillOptions {
  /** Replace what's already in the fields (the user picked the item in the popup). */
  overwrite?: boolean;
}

const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

/** "03/27", "3/27", "03/2027", "0327", "03-27" → month 3, year 2027; null if it doesn't parse. */
export function parseExpiry(text: string): { month: number; year: number } | null {
  const trimmed = text.trim();
  const match =
    /^(\d{1,2})\s*[/\-.\s]\s*(\d{2}|\d{4})$/.exec(trimmed) ??
    /^(\d{2})(\d{2}|\d{4})$/.exec(trimmed);
  if (!match) return null;
  const month = Number(match[1]);
  const year = match[2]!.length === 2 ? 2000 + Number(match[2]) : Number(match[2]);
  return month >= 1 && month <= 12 ? { month, year } : null;
}

/**
 * Picks the first option whose value or text matches a candidate (ignoring
 * case and spaces at the ends), the way a user would. False if none does.
 */
export function setSelectValue(select: HTMLSelectElement, candidates: readonly string[]): boolean {
  const wanted = candidates.map((c) => c.trim().toLowerCase()).filter(Boolean);
  const index = [...select.options].findIndex(
    (option) =>
      wanted.includes(option.value.trim().toLowerCase()) ||
      wanted.includes(option.text.trim().toLowerCase()),
  );
  if (index === -1) return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex')?.set;
  if (setter) setter.call(select, index);
  else select.selectedIndex = index;
  select.dispatchEvent(new Event('input', { bubbles: true }));
  select.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

/**
 * Fills one field with the first candidate (inputs) or the first matching
 * option (selects). Inputs that already hold something are left alone
 * unless `overwrite`; selects always have a value, so they're always set.
 */
function fill(
  field: FillableField | undefined,
  candidates: readonly string[],
  { overwrite = false }: FillOptions,
): boolean {
  if (!field || !candidates[0]) return false;
  if (field instanceof HTMLSelectElement) return setSelectValue(field, candidates);
  if (field.value && !overwrite) return false;
  setFieldValue(field, candidates[0]);
  return true;
}

const pad = (n: number) => String(n).padStart(2, '0');

/** Does a field want a four-digit year (room for it, or a placeholder asking)? */
const wantsLongYear = (field: FillableField, digitsBeforeYear: number) =>
  field instanceof HTMLInputElement &&
  (/yyyy/i.test(field.placeholder) || field.maxLength >= digitsBeforeYear + 4);

/** Fills a card form with a saved card's fields; returns how many fields it filled. */
export function fillCardForm(
  form: DetectedForm<CardKey>,
  card: Readonly<Record<string, string>>,
  options: FillOptions = {},
): number {
  const { fields } = form;
  let filled = 0;
  const put = (field: FillableField | undefined, candidates: string[]) => {
    if (fill(field, candidates, options)) filled++;
  };
  put(fields.cardholder, [card.cardholder ?? '']);
  // Digits only: most number fields add their own spacing as you type.
  put(fields.number, [(card.number ?? '').replace(/\D/g, '')]);
  put(fields.cvv, [card.cvv ?? '']);

  const expiry = parseExpiry(card.expiry ?? '');
  if (expiry) {
    const { month, year } = expiry;
    const short = String(year).slice(-2);
    if (fields.expiry) {
      put(fields.expiry, [`${pad(month)}/${wantsLongYear(fields.expiry, 3) ? year : short}`]);
    }
    const name = MONTHS[month - 1]!;
    put(fields.expMonth, [pad(month), String(month), name, name.slice(0, 3)]);
    if (fields.expYear) {
      const yearField = fields.expYear;
      // A year field with no length limit gets all four digits.
      const long =
        yearField instanceof HTMLSelectElement ||
        yearField.maxLength === -1 ||
        wantsLongYear(yearField, 0);
      put(fields.expYear, long ? [String(year), short] : [short, String(year)]);
    }
  }
  return filled;
}

/** Fills an address form with a saved identity's fields; returns how many fields it filled. */
export function fillIdentityForm(
  form: DetectedForm<IdentityKey>,
  identity: Readonly<Record<string, string>>,
  options: FillOptions = {},
): number {
  const { fields } = form;
  const fullName = [identity.firstName, identity.lastName].filter(Boolean).join(' ');
  const values: Record<IdentityKey, string> = {
    fullName,
    firstName: identity.firstName ?? '',
    lastName: identity.lastName ?? '',
    email: identity.email ?? '',
    phone: identity.phone ?? '',
    address: identity.address ?? '',
    city: identity.city ?? '',
    postalCode: identity.postalCode ?? '',
    country: identity.country ?? '',
  };
  let filled = 0;
  for (const key of Object.keys(values) as IdentityKey[]) {
    if (fill(fields[key], [values[key]], options)) filled++;
  }
  return filled;
}
