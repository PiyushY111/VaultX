// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { findCardForm, findIdentityForm } from '../src/content/detectForms';
import {
  fillCardForm,
  fillIdentityForm,
  parseExpiry,
  setSelectValue,
} from '../src/content/fillForms';

const html = (markup: string) => {
  document.body.innerHTML = markup;
};
const value = (id: string) =>
  (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;

const CARD = { cardholder: 'Jane Doe', number: '4111 1111 1111 1111', expiry: '03/27', cvv: '123' };

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('parseExpiry', () => {
  it.each(['03/27', '3/27', '03/2027', '0327', '03-27', ' 03 / 27 ', '032027'])(
    'reads %j as March 2027',
    (text) => {
      expect(parseExpiry(text)).toEqual({ month: 3, year: 2027 });
    },
  );

  it.each(['soon', '13/27', '00/27', '', '3/7'])('refuses %j', (text) => {
    expect(parseExpiry(text)).toBeNull();
  });
});

describe('fillCardForm', () => {
  it('fills a card form, number without spaces, and fires input and change events', () => {
    html(`<form>
      <input id="name" autocomplete="cc-name">
      <input id="num" autocomplete="cc-number">
      <input id="exp" autocomplete="cc-exp" maxlength="5">
      <input id="cvc" autocomplete="cc-csc">
    </form>`);
    const events: string[] = [];
    document.getElementById('num')!.addEventListener('input', () => events.push('input'));
    document.getElementById('num')!.addEventListener('change', () => events.push('change'));

    fillCardForm(findCardForm(document)!, CARD);
    expect([value('name'), value('num'), value('exp'), value('cvc')]).toEqual([
      'Jane Doe',
      '4111111111111111',
      '03/27',
      '123',
    ]);
    expect(events).toEqual(['input', 'change']);
  });

  it('writes a four-digit year where the field has room or asks for one', () => {
    html(
      `<form><input autocomplete="cc-number"><input id="exp" autocomplete="cc-exp" maxlength="7"></form>`,
    );
    fillCardForm(findCardForm(document)!, CARD);
    expect(value('exp')).toBe('03/2027');
    html(
      `<form><input autocomplete="cc-number"><input id="exp" autocomplete="cc-exp" placeholder="MM/YYYY"></form>`,
    );
    fillCardForm(findCardForm(document)!, CARD);
    expect(value('exp')).toBe('03/2027');
  });

  it.each([
    ['numbers', '<option value="1">1</option><option value="3">3</option>', '3'],
    ['padded', '<option value="01">01</option><option value="03">03</option>', '03'],
    ['names', '<option value="jan">January</option><option value="mar">March</option>', 'mar'],
  ])('picks the month from a select of %s', (_, options, expected) => {
    html(`<form>
      <input autocomplete="cc-number">
      <select id="m" autocomplete="cc-exp-month"><option value="">Month</option>${options}</select>
      <select id="y" autocomplete="cc-exp-year"><option value="26">26</option><option value="27">27</option></select>
    </form>`);
    fillCardForm(findCardForm(document)!, CARD);
    expect(value('m')).toBe(expected);
    expect(value('y')).toBe('27');
  });

  it('fills year inputs with four digits unless they only take two', () => {
    html(`<form>
      <input autocomplete="cc-number">
      <input id="m" autocomplete="cc-exp-month"><input id="y" autocomplete="cc-exp-year">
    </form>`);
    fillCardForm(findCardForm(document)!, CARD);
    expect([value('m'), value('y')]).toEqual(['03', '2027']);
    html(
      `<form><input autocomplete="cc-number"><input autocomplete="cc-exp-month"><input id="y" autocomplete="cc-exp-year" maxlength="2"></form>`,
    );
    fillCardForm(findCardForm(document)!, CARD);
    expect(value('y')).toBe('27');
  });

  it('leaves the expiry alone when the saved one can’t be read', () => {
    html(`<form><input autocomplete="cc-number"><input id="exp" autocomplete="cc-exp"></form>`);
    fillCardForm(findCardForm(document)!, { ...CARD, expiry: 'whenever' });
    expect(value('exp')).toBe('');
  });

  it('doesn’t overwrite what the user typed, unless asked', () => {
    html(
      `<form><input id="num" autocomplete="cc-number"><input id="name" autocomplete="cc-name" value="J. Doe"></form>`,
    );
    fillCardForm(findCardForm(document)!, CARD);
    expect(value('name')).toBe('J. Doe');
    expect(value('num')).toBe('4111111111111111');
    fillCardForm(findCardForm(document)!, CARD, { overwrite: true });
    expect(value('name')).toBe('Jane Doe');
  });

  it('uses the native setter, so a page can’t intercept the value property', () => {
    html(`<form><input id="num" autocomplete="cc-number"><input autocomplete="cc-csc"></form>`);
    const num = document.getElementById('num') as HTMLInputElement;
    const spy = vi.fn();
    Object.defineProperty(num, 'value', { set: spy, get: () => '', configurable: true });
    fillCardForm(findCardForm(document)!, CARD);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('fillIdentityForm', () => {
  const IDENTITY = {
    firstName: 'Jane',
    lastName: 'Doe',
    email: 'jane@example.com',
    phone: '+49 30 1234567',
    address: 'Hauptstr. 1',
    city: 'Berlin',
    postalCode: '10115',
    country: 'Germany',
  };

  it('fills an address form, joining first and last name for a full-name field', () => {
    html(`<form>
      <input id="n" autocomplete="name">
      <input id="a" autocomplete="street-address">
      <input id="c" autocomplete="address-level2">
      <input id="z" autocomplete="postal-code">
      <select id="k" autocomplete="country">
        <option value="">Choose</option><option value="FR">France</option><option value="DE">Germany</option>
      </select>
    </form>`);
    fillIdentityForm(findIdentityForm(document)!, IDENTITY);
    expect(['n', 'a', 'c', 'z', 'k'].map(value)).toEqual([
      'Jane Doe',
      'Hauptstr. 1',
      'Berlin',
      '10115',
      'DE',
    ]);
  });

  it('leaves a country select alone when nothing matches', () => {
    html(`<form>
      <input autocomplete="street-address"><input autocomplete="address-level2">
      <select id="k" autocomplete="country"><option value="">Choose</option><option>France</option></select>
    </form>`);
    fillIdentityForm(findIdentityForm(document)!, IDENTITY);
    expect(value('k')).toBe('');
  });
});

describe('setSelectValue', () => {
  it('matches an option’s value or text, ignoring case, and reports a miss', () => {
    html(`<select id="s"><option value="a">Alpha</option><option value="b">Beta</option></select>`);
    const select = document.getElementById('s') as HTMLSelectElement;
    expect(setSelectValue(select, ['BETA'])).toBe(true);
    expect(select.value).toBe('b');
    expect(setSelectValue(select, ['gamma'])).toBe(false);
    expect(select.value).toBe('b');
  });
});
