// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest';
import { findCardForm, findIdentityForm } from '../src/content/detectForms';

const html = (markup: string) => {
  document.body.innerHTML = markup;
};
const ids = (fields: Partial<Record<string, Element>>) =>
  Object.fromEntries(Object.entries(fields).map(([key, field]) => [key, field?.id]));

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('findCardForm', () => {
  it('reads autocomplete tokens', () => {
    html(`<form>
      <input id="name" autocomplete="cc-name">
      <input id="num" autocomplete="cc-number">
      <select id="mm" autocomplete="cc-exp-month"><option>01</option></select>
      <select id="yy" autocomplete="cc-exp-year"><option>2027</option></select>
      <input id="cvc" autocomplete="cc-csc">
    </form>`);
    const form = findCardForm(document);
    expect(ids(form!.fields)).toEqual({
      cardholder: 'name',
      number: 'num',
      expMonth: 'mm',
      expYear: 'yy',
      cvv: 'cvc',
    });
    expect(form!.anchor.id).toBe('num');
  });

  it('reads section and billing prefixes, and a single expiry field', () => {
    html(`<form>
      <input id="num" autocomplete="section-pay billing cc-number">
      <input id="exp" autocomplete="section-pay billing cc-exp">
    </form>`);
    expect(ids(findCardForm(document)!.fields)).toEqual({ number: 'num', expiry: 'exp' });
  });

  it('falls back to names, ids, placeholders and labels', () => {
    html(`<form>
      <label for="a">Name on card</label><input id="a">
      <input id="b" name="cardNumber">
      <input id="c" placeholder="MM / YY" name="expiry">
      <input id="d" aria-label="Security code" maxlength="4">
    </form>`);
    expect(ids(findCardForm(document)!.fields)).toEqual({
      cardholder: 'a',
      number: 'b',
      expiry: 'c',
      cvv: 'd',
    });
  });

  it('tells expiry month and year fields apart', () => {
    html(`<form>
      <input id="n" name="cc_number">
      <select id="m" name="exp_month"><option>1</option></select>
      <select id="y" name="expYear"><option>2030</option></select>
    </form>`);
    expect(ids(findCardForm(document)!.fields)).toEqual({
      number: 'n',
      expMonth: 'm',
      expYear: 'y',
    });
  });

  it('needs a card number plus one more card field', () => {
    html(`<form><input autocomplete="cc-number"></form>`);
    expect(findCardForm(document)).toBeNull();
    html(`<form><input name="cvv"><input name="search"></form>`);
    expect(findCardForm(document)).toBeNull();
  });

  it('offers the name on card alone when the number is in a payment iframe', () => {
    html(`<form>
      <input id="holder" autocomplete="cc-name">
      <iframe src="https://js.stripe.com/v3/elements-inner-card.html"></iframe>
    </form>`);
    const form = findCardForm(document);
    expect(ids(form!.fields)).toEqual({ cardholder: 'holder' });
    html(`<form><input autocomplete="cc-name"></form>`);
    expect(findCardForm(document)).toBeNull();
  });

  it('ignores hidden, disabled and password fields, and login pages', () => {
    html(`<form>
      <input autocomplete="cc-number" type="hidden">
      <input autocomplete="cc-number" disabled>
      <input autocomplete="cc-csc" type="password">
      <input autocomplete="cc-exp">
    </form>`);
    expect(findCardForm(document)).toBeNull();
    html(`<form>
      <input autocomplete="cc-number"><input autocomplete="cc-exp">
      <input type="text" name="user"><input type="password">
    </form>`);
    expect(findCardForm(document)).toBeNull();
  });
});

describe('findIdentityForm', () => {
  const ADDRESS = `
    <input id="first" autocomplete="given-name">
    <input id="last" autocomplete="family-name">
    <input id="street" autocomplete="address-line1">
    <input id="city" autocomplete="address-level2">
    <input id="zip" autocomplete="postal-code">
    <select id="country" autocomplete="country"><option>Germany</option></select>
    <input id="mail" type="email">
    <input id="tel" type="tel">`;

  it('reads an address form', () => {
    html(`<form>${ADDRESS}</form>`);
    expect(ids(findIdentityForm(document)!.fields)).toEqual({
      firstName: 'first',
      lastName: 'last',
      address: 'street',
      city: 'city',
      postalCode: 'zip',
      country: 'country',
      email: 'mail',
      phone: 'tel',
    });
  });

  it('falls back to field names, and knows a full-name field', () => {
    html(`<form>
      <input id="n" name="name">
      <input id="a" name="street_address">
      <input id="t" name="town">
      <input id="z" placeholder="ZIP code">
    </form>`);
    expect(ids(findIdentityForm(document)!.fields)).toEqual({
      fullName: 'n',
      address: 'a',
      city: 't',
      postalCode: 'z',
    });
  });

  it('takes the first complete section when shipping and billing both appear', () => {
    html(`<form>
      <input id="s-street" autocomplete="shipping street-address">
      <input id="s-city" autocomplete="shipping address-level2">
      <input id="s-zip" autocomplete="shipping postal-code">
      <input id="b-street" autocomplete="billing street-address">
      <input id="b-city" autocomplete="billing address-level2">
      <input id="b-zip" autocomplete="billing postal-code">
    </form>`);
    expect(ids(findIdentityForm(document)!.fields)).toEqual({
      address: 's-street',
      city: 's-city',
      postalCode: 's-zip',
    });
  });

  it('isn’t fooled by a newsletter form or an email address field', () => {
    html(`<form><input name="name"><input type="email" name="email_address"></form>`);
    expect(findIdentityForm(document)).toBeNull();
  });

  it('stays out of login pages', () => {
    html(`<form>${ADDRESS}<input type="password"></form>`);
    expect(findIdentityForm(document)).toBeNull();
  });
});
