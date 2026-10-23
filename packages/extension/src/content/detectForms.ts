/**
 * Card and address form detection. Pure DOM helpers, like detect.ts. Cards
 * and identities aren't tied to a site, so these decide when to offer one:
 * only on forms that clearly ask for them, never on a login form.
 */
import { findLoginFields, isUsable, words } from './detect';

export type CardKey = 'cardholder' | 'number' | 'expiry' | 'expMonth' | 'expYear' | 'cvv';
export type IdentityKey =
  | 'fullName'
  | 'firstName'
  | 'lastName'
  | 'email'
  | 'phone'
  | 'address'
  | 'city'
  | 'postalCode'
  | 'country';

export type FillableField = HTMLInputElement | HTMLSelectElement;

export interface DetectedForm<K extends string> {
  fields: Partial<Record<K, FillableField>>;
  /** Where the prompt goes: the field the form is mostly about. */
  anchor: FillableField;
}

/** The autocomplete field names (WHATWG) each key stands for. */
const CARD_TOKENS: Record<string, CardKey> = {
  'cc-name': 'cardholder',
  'cc-number': 'number',
  'cc-exp': 'expiry',
  'cc-exp-month': 'expMonth',
  'cc-exp-year': 'expYear',
  'cc-csc': 'cvv',
};
const IDENTITY_TOKENS: Record<string, IdentityKey> = {
  name: 'fullName',
  'given-name': 'firstName',
  'family-name': 'lastName',
  email: 'email',
  tel: 'phone',
  'street-address': 'address',
  'address-line1': 'address',
  'address-level2': 'city',
  'postal-code': 'postalCode',
  country: 'country',
  'country-name': 'country',
};

// Used only when a field has no autocomplete token, on its name, id,
// placeholder, aria-label and label text (split into words). Order matters:
// the security code and email before anything that could also match them.
const CARD_HINTS: [CardKey, RegExp][] = [
  ['cvv', /\b(cvc|cvv|cvv2|cvn|csc|cid|security ?code|card ?verification)\b/i],
  ['cardholder', /\b(card ?holder|name ?on ?card|holder ?name|cc ?name)\b/i],
  ['number', /\b(card ?(number|no|num)|cc ?(number|num|no)|cardnumber|ccnumber)\b/i],
];
const EXPIRY_HINT = /\b(exp(iry|ires|iration)?|valid ?(thru|through|until))\b/i;
const MONTH_HINT = /\b(mm|month)\b/i;
const YEAR_HINT = /\b(yy|yyyy|year)\b/i;

const IDENTITY_HINTS: [IdentityKey, RegExp][] = [
  ['email', /\be-?mail\b/i],
  ['phone', /\b(phone|mobile|tel|telephone)\b/i],
  ['firstName', /\b(first ?name|given ?name|fname|forename)\b/i],
  ['lastName', /\b(last ?name|family ?name|surname|lname)\b/i],
  ['postalCode', /\b(zip|postal|post ?code|postcode)\b/i],
  ['city', /\b(city|town|locality)\b/i],
  ['country', /\bcountry\b/i],
  ['address', /\b(street|address|addr1|address1|address ?line ?1?)\b/i],
  ['fullName', /^\s*(full ?name|your ?name|name)\s*$/i],
];

/** Payment providers whose card fields live in their own iframe, out of our reach. */
const PAYMENT_FRAME = /(stripe|braintree|adyen|checkout\.com|squareup|paypal)/i;

/** The autocomplete field name and its section ("section-x billing"), if any. */
function autocompleteOf(field: FillableField): { token: string; section: string } | null {
  const tokens = (field.getAttribute('autocomplete') ?? '').toLowerCase().trim().split(/\s+/);
  const named = tokens.filter((token) => token && token !== 'webauthn');
  const token = named.at(-1);
  if (!token || token === 'on' || token === 'off') return null;
  const section = named.filter((t) => t.startsWith('section-') || /^(shipping|billing)$/.test(t));
  return { token, section: section.join(' ') };
}

function describe(field: FillableField): string {
  const label = field.labels?.[0]?.textContent ?? '';
  const placeholder = field instanceof HTMLInputElement ? field.placeholder : '';
  return words(
    [field.name, field.id, placeholder, field.getAttribute('aria-label') ?? '', label].join(' '),
  );
}

function cardKey(field: FillableField): CardKey | null {
  const text = describe(field);
  for (const [key, hint] of CARD_HINTS) if (hint.test(text)) return key;
  if (!EXPIRY_HINT.test(text) && !/\bmm ?\/ ?yy/i.test(text)) return null;
  const month = MONTH_HINT.test(text);
  const year = YEAR_HINT.test(text);
  // "MM / YY" in one field is the whole expiry date.
  if (month && !year) return 'expMonth';
  if (year && !month) return 'expYear';
  return 'expiry';
}

function identityKey(field: FillableField): IdentityKey | null {
  if (field instanceof HTMLInputElement && field.type === 'email') return 'email';
  if (field instanceof HTMLInputElement && field.type === 'tel') return 'phone';
  // A whole-field match for a bare "name", so "username" or "company name" don't count.
  const text = describe(field);
  for (const [key, hint] of IDENTITY_HINTS) {
    if (
      key === 'fullName' ? [field.name, field.id].some((v) => hint.test(words(v))) : hint.test(text)
    )
      return key;
  }
  return null;
}

interface Group<K extends string> {
  fields: Partial<Record<K, FillableField>>;
  order: K[];
  scope: Element | null;
}

const FILLABLE =
  'input:not([type]), input[type="text"], input[type="email"], input[type="tel"], input[type="number"], input[type="search"], select';

/**
 * The fields `classify` recognizes, grouped by form and autocomplete section
 * (so shipping and billing addresses stay apart), in document order.
 */
function groups<K extends string>(
  doc: Document,
  tokens: Record<string, K>,
  classify: (field: FillableField) => K | null,
): Group<K>[] {
  const found = new Map<string, Group<K>>();
  const ids = new Map<Element | null, number>();
  for (const field of doc.querySelectorAll<FillableField>(FILLABLE)) {
    if (!isUsable(field)) continue;
    const auto = autocompleteOf(field);
    const key = auto ? (tokens[auto.token] ?? null) : classify(field);
    if (!key) continue;
    if (!ids.has(field.form)) ids.set(field.form, ids.size);
    const groupId = `${ids.get(field.form)}|${auto?.section ?? ''}`;
    const group: Group<K> = found.get(groupId) ?? { fields: {}, order: [], scope: field.form };
    if (!group.fields[key]) {
      group.fields[key] = field;
      group.order.push(key);
    }
    found.set(groupId, group);
  }
  // Fields with no section join their form's first complete section (e.g. an email field).
  const all = [...found.entries()];
  for (const [id, group] of all) {
    if (!id.endsWith('|')) continue;
    const owner = all.find(([other, g]) => other !== id && g.scope === group.scope)?.[1];
    if (!owner) continue;
    for (const key of group.order) {
      if (owner.fields[key]) continue;
      owner.fields[key] = group.fields[key];
      owner.order.push(key);
    }
  }
  return [...found.values()];
}

/** A checkout form: a card number plus another card field, or just the name on the card when the number sits in a payment provider's iframe. */
export function findCardForm(doc: Document): DetectedForm<CardKey> | null {
  if (findLoginFields(doc).length > 0) return null;
  for (const { fields, scope } of groups(doc, CARD_TOKENS, cardKey)) {
    const others = (['expiry', 'expMonth', 'cvv', 'cardholder'] as const).some((k) => fields[k]);
    if (fields.number && others) return { fields, anchor: fields.number };
    const frames = [...(scope ?? doc).querySelectorAll('iframe')];
    if (fields.cardholder && frames.some((frame) => PAYMENT_FRAME.test(frame.src))) {
      return { fields: { cardholder: fields.cardholder }, anchor: fields.cardholder };
    }
  }
  return null;
}

/** An address form: three or more identity fields, one of them part of an address. */
export function findIdentityForm(doc: Document): DetectedForm<IdentityKey> | null {
  if (findLoginFields(doc).length > 0) return null;
  for (const { fields, order } of groups(doc, IDENTITY_TOKENS, identityKey)) {
    const address = fields.address ?? fields.postalCode ?? fields.city;
    if (address && order.length >= 3) return { fields, anchor: fields[order[0]!]! };
  }
  return null;
}
