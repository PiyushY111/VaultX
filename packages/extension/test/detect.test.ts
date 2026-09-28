// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fillLogin,
  findLoginFields,
  findOtpField,
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
