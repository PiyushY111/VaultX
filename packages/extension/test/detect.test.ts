// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fillGeneratedPassword,
  fillLogin,
  fillOtp,
  findLoginFields,
  findOtpField,
  findOtpTarget,
  findUsernameField,
  readSubmittedCredential,
} from '../src/content/detect';

const html = (markup: string) => {
  document.body.innerHTML = markup;
};

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('findLoginFields', () => {
  it('finds a classic username + password form', () => {
    html(
      `<form id="f"><input id="u" type="text" name="login"><input id="p" type="password"><button>Sign in</button></form>`,
    );
    const [fields] = findLoginFields(document);
    expect(fields?.form?.id).toBe('f');
    expect(fields?.username?.id).toBe('u');
    expect(fields?.password.id).toBe('p');
  });

  it('prefers a field marked autocomplete=username over a nearer text field', () => {
    html(
      `<form><input id="email" type="email" autocomplete="username"><input id="otp" type="text"><input id="p" type="password"></form>`,
    );
    expect(findLoginFields(document)[0]?.username?.id).toBe('email');
  });

  it('handles form-less logins', () => {
    html(
      `<div><input id="search" type="search"><input id="u" type="email"><input id="p" type="password"></div>`,
    );
    const [fields] = findLoginFields(document);
    expect(fields?.form).toBeNull();
    expect(fields?.username?.id).toBe('u');
  });

  it('ignores hidden, disabled and read-only password fields', () => {
    html(`
      <form><input type="password" hidden></form>
      <form><input type="password" style="display:none"></form>
      <div style="visibility:hidden"><form><input type="password"></form></div>
      <form><input type="password" disabled></form>
      <form><input type="password" readonly></form>
    `);
    expect(findLoginFields(document)).toEqual([]);
  });

  it('returns one entry per form', () => {
    html(`
      <form id="login"><input type="text"><input type="password"></form>
      <form id="signup"><input type="email"><input type="password"><input type="password"></form>
    `);
    expect(findLoginFields(document).map((f) => f.form?.id)).toEqual(['login', 'signup']);
  });

  it('returns null username when there is no candidate', () => {
    html(`<form><input id="p" type="password"></form>`);
    expect(findUsernameField(document.getElementById('p') as HTMLInputElement)).toBeNull();
  });
});

describe('fillLogin', () => {
  it('sets values and fires input/change events for frameworks', () => {
    html(`<form><input id="u" type="text"><input id="p" type="password"></form>`);
    const [fields] = findLoginFields(document);
    const events: string[] = [];
    for (const input of [fields!.username!, fields!.password]) {
      input.addEventListener('input', () => events.push(`input:${input.id}`));
      input.addEventListener('change', () => events.push(`change:${input.id}`));
    }
    fillLogin(fields!, 'alice', 's3cret');
    expect(fields!.username!.value).toBe('alice');
    expect(fields!.password.value).toBe('s3cret');
    expect(events).toEqual(['input:u', 'change:u', 'input:p', 'change:p']);
  });

  it('uses the native setter even if the page overrides the value property', () => {
    html(`<form><input id="u" type="text"><input id="p" type="password"></form>`);
    const [fields] = findLoginFields(document);
    const spy = vi.fn();
    Object.defineProperty(fields!.password, 'value', {
      set: spy,
      get: () => 'fake',
      configurable: true,
    });
    fillLogin(fields!, 'alice', 's3cret');
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('readSubmittedCredential', () => {
  it('reads username and password', () => {
    html(
      `<form id="f"><input type="email" value=" alice@example.com "><input type="password" value="pw1"></form>`,
    );
    expect(readSubmittedCredential(document.getElementById('f')!)).toEqual({
      username: 'alice@example.com',
      password: 'pw1',
    });
  });

  it('takes the new password on change-password forms', () => {
    html(
      `<form id="f"><input type="text" value="alice"><input type="password" value="old"><input type="password" value="new"></form>`,
    );
    expect(readSubmittedCredential(document.getElementById('f')!)).toEqual({
      username: 'alice',
      password: 'new',
    });
  });

  it('returns null when no password was entered', () => {
    html(`<form id="f"><input type="text" value="alice"><input type="password"></form>`);
    expect(readSubmittedCredential(document.getElementById('f')!)).toBeNull();
  });
});

describe('findOtpField', () => {
  it.each([
    ['autocomplete="one-time-code"', '<input id="x" autocomplete="one-time-code">'],
    ['a name like otp_code', '<input id="x" name="otp_code" maxlength="6">'],
    ['a camelCase id like totpCode', '<input id="x" name="totpCode" inputmode="numeric">'],
    ['a label', '<label for="x">Authentication code</label><input id="x" type="tel">'],
    ['a placeholder', '<input id="x" placeholder="6-digit 2FA code">'],
  ])('finds a code field by %s', (_, markup) => {
    html(`<form>${markup}</form>`);
    expect(findOtpField(document)?.id).toBe('x');
  });

  it.each([
    ['a login form', '<input name="otp"><input type="password">'],
    ['an ordinary text field', '<input name="search" placeholder="Search">'],
    ['a word that merely contains "otp"', '<input name="footprint">'],
    ['a code field too long for a code', '<input name="otp" maxlength="20">'],
    ['a hidden code field', '<input name="otp" hidden>'],
  ])('ignores %s', (_, markup) => {
    html(`<form>${markup}</form>`);
    expect(findOtpField(document)).toBeNull();
  });
});

/** `count` single-digit boxes, each wrapped in `wrap` (e.g. "<div>$</div>") if given. */
const boxes = (count: number, { first = '', wrap = '$' } = {}) =>
  Array.from({ length: count }, (_, i) =>
    wrap.replace(
      '$',
      `<input id="b${i}" maxlength="1" inputmode="numeric"${i === 0 ? ` ${first}` : ''}>`,
    ),
  ).join('');
const splitIds = () => {
  const target = findOtpTarget(document);
  return target?.kind === 'split' ? target.inputs.map((input) => input.id) : null;
};

describe('findOtpTarget: codes split into one box per digit', () => {
  it('finds six boxes with autocomplete="one-time-code" on the first', () => {
    html(`<form>${boxes(6, { first: 'autocomplete="one-time-code"' })}</form>`);
    expect(splitIds()).toEqual(['b0', 'b1', 'b2', 'b3', 'b4', 'b5']);
  });

  it('finds boxes wrapped one per element, under a labelled container', () => {
    html(
      `<form><div aria-label="Verification code">${boxes(6, { wrap: '<div>$</div>' })}</div></form>`,
    );
    expect(splitIds()).toHaveLength(6);
  });

  it('finds boxes under a heading that names the step', () => {
    html(
      `<main><h1>Two-factor authentication</h1><section><div>${boxes(6)}</div></section></main>`,
    );
    expect(splitIds()).toHaveLength(6);
  });

  it('ignores digit boxes with no hint they want a code (a PIN pad, card digits…)', () => {
    html(`<form><h2>Enter your PIN</h2>${boxes(6)}</form>`);
    expect(findOtpTarget(document)).toBeNull();
  });

  it.each([
    [3, false],
    [4, true],
    [8, true],
    [9, false],
  ])('with %i boxes, finds a code: %s', (count, found) => {
    html(`<form aria-label="Security code">${boxes(count)}</form>`);
    expect(splitIds() !== null).toBe(found);
  });

  it('prefers a single code field when the page has one', () => {
    html(
      `<form aria-label="Security code"><input id="x" autocomplete="one-time-code" maxlength="6">${boxes(6)}</form>`,
    );
    expect(findOtpTarget(document)).toMatchObject({ kind: 'single', input: { id: 'x' } });
  });

  it('stays out of login forms', () => {
    html(`<form aria-label="Security code">${boxes(6)}<input type="password"></form>`);
    expect(findOtpTarget(document)).toBeNull();
  });

  it('picks the group of six over a shorter one', () => {
    html(`<form aria-label="Verification code">
      <div>${boxes(4).replaceAll('id="b', 'id="short')}</div>
      <input name="between" placeholder="Phone">
      <div>${boxes(6)}</div>
    </form>`);
    expect(splitIds()).toEqual(['b0', 'b1', 'b2', 'b3', 'b4', 'b5']);
  });

  it('doesn’t join boxes across a hidden or disabled box', () => {
    html(
      `<form aria-label="Security code">${boxes(3)}<input maxlength="1" hidden>${boxes(3).replaceAll('id="b', 'id="c')}</form>`,
    );
    expect(findOtpTarget(document)).toBeNull();
  });

  it('keeps findOtpField working for single fields only', () => {
    html(`<form>${boxes(6, { first: 'autocomplete="one-time-code"' })}</form>`);
    expect(findOtpField(document)).toBeNull();
  });
});

describe('fillOtp', () => {
  const values = () =>
    [...document.querySelectorAll<HTMLInputElement>('input')].map((input) => input.value);

  it('fills a single field with the whole code', () => {
    html('<input id="x" autocomplete="one-time-code">');
    expect(fillOtp(findOtpTarget(document)!, '123456')).toBe(true);
    expect(values()).toEqual(['123456']);
  });

  it('types one digit per box, with input events on each', () => {
    html(`<form aria-label="Security code">${boxes(6)}</form>`);
    const events: string[] = [];
    for (const input of document.querySelectorAll('input'))
      input.addEventListener('input', () => events.push(input.id));
    expect(fillOtp(findOtpTarget(document)!, '123456')).toBe(true);
    expect(values()).toEqual(['1', '2', '3', '4', '5', '6']);
    expect(events).toEqual(['b0', 'b1', 'b2', 'b3', 'b4', 'b5']);
  });

  it('falls back to pasting the code when the boxes only take a paste', () => {
    html(`<form aria-label="Security code">${boxes(6)}</form>`);
    const inputs = [...document.querySelectorAll<HTMLInputElement>('input')];
    // Like some OTP widgets: typed values are rejected, a paste spreads across the boxes.
    for (const input of inputs) input.addEventListener('input', () => (input.value = ''));
    inputs[0]!.addEventListener('paste', (event) => {
      const text = (event as ClipboardEvent).clipboardData!.getData('text/plain');
      inputs.forEach((input, i) => (input.value = text[i] ?? ''));
      event.preventDefault();
    });
    expect(fillOtp(findOtpTarget(document)!, '987654')).toBe(true);
    expect(values()).toEqual(['9', '8', '7', '6', '5', '4']);
  });

  it('refuses a code that doesn’t fit the boxes, changing nothing', () => {
    html(`<form aria-label="Security code">${boxes(6)}</form>`);
    expect(fillOtp(findOtpTarget(document)!, '12345678')).toBe(false);
    expect(values().join('')).toBe('');
  });

  it('reports a failure when neither typing nor pasting works', () => {
    html(`<form aria-label="Security code">${boxes(6)}</form>`);
    for (const input of document.querySelectorAll('input'))
      input.addEventListener('input', () => (input.value = ''));
    expect(fillOtp(findOtpTarget(document)!, '123456')).toBe(false);
  });
});

describe('fillGeneratedPassword', () => {
  const value = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
  const SIGNUP = `<form id="signup">
      <input id="user" type="email">
      <input id="pw" type="password">
      <input id="confirm" type="password">
    </form>
    <form><input id="other" type="password"></form>`;

  it('fills the right-clicked field and the empty confirmation in its form, nothing else', () => {
    html(SIGNUP);
    const filled = fillGeneratedPassword(
      document.getElementById('pw') as HTMLInputElement,
      document,
      'G3n!',
    );
    expect(filled).toBe(2);
    expect([value('pw'), value('confirm'), value('other'), value('user')]).toEqual([
      'G3n!',
      'G3n!',
      '',
      '',
    ]);
  });

  it('leaves a confirmation field the user already typed in', () => {
    html(SIGNUP);
    (document.getElementById('confirm') as HTMLInputElement).value = 'typed';
    fillGeneratedPassword(document.getElementById('pw') as HTMLInputElement, document, 'G3n!');
    expect(value('confirm')).toBe('typed');
  });

  it('without a usable right-clicked field, uses the first empty password field’s form', () => {
    html(SIGNUP);
    expect(fillGeneratedPassword(null, document, 'G3n!')).toBe(2);
    expect([value('pw'), value('confirm'), value('other')]).toEqual(['G3n!', 'G3n!', '']);
    html('<form><input id="h" type="password" hidden></form>');
    expect(
      fillGeneratedPassword(document.getElementById('h') as HTMLInputElement, document, 'x'),
    ).toBe(0);
  });
});
