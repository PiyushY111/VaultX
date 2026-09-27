import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  entropyBits,
  generatePassword,
  randomInt,
} from './passwordGenerator';

const hasDigit = (s: string) => /[0-9]/.test(s);
const hasSymbol = (s: string) => /[^A-Za-z0-9]/.test(s);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('generatePassword', () => {
  it.each([MIN_PASSWORD_LENGTH, 20, 64, MAX_PASSWORD_LENGTH])(
    'produces exactly %i characters',
    (length) => {
      expect(generatePassword({ length, numbers: true, symbols: true })).toHaveLength(length);
    },
  );

  it('always includes lowercase, uppercase, and every enabled class', () => {
    for (let i = 0; i < 200; i++) {
      const password = generatePassword({
        length: MIN_PASSWORD_LENGTH,
        numbers: true,
        symbols: true,
      });
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(hasDigit(password)).toBe(true);
      expect(hasSymbol(password)).toBe(true);
    }
  });

  it('omits numbers and symbols when they are turned off', () => {
    for (let i = 0; i < 200; i++) {
      const password = generatePassword({ length: 32, numbers: false, symbols: false });
      expect(password).toMatch(/^[A-Za-z]+$/);
    }
    const noSymbols = generatePassword({ length: 64, numbers: true, symbols: false });
    expect(hasSymbol(noSymbols)).toBe(false);
    const noNumbers = generatePassword({ length: 64, numbers: false, symbols: true });
    expect(hasDigit(noNumbers)).toBe(false);
  });

  it('does not repeat', () => {
    const passwords = new Set(
      Array.from({ length: 500 }, () =>
        generatePassword({ length: 16, numbers: true, symbols: true }),
      ),
    );
    expect(passwords.size).toBe(500);
  });

  it('uses crypto.getRandomValues, never Math.random', () => {
    const mathRandom = vi.spyOn(Math, 'random');
    const getRandomValues = vi.spyOn(crypto, 'getRandomValues');
    generatePassword({ length: 20, numbers: true, symbols: true });
    expect(mathRandom).not.toHaveBeenCalled();
    expect(getRandomValues).toHaveBeenCalled();
  });

  it.each([0, 7, 129, 12.5, Number.NaN])('rejects length %s', (length) => {
    expect(() => generatePassword({ length, numbers: true, symbols: true })).toThrow(RangeError);
  });
});

describe('randomInt', () => {
  it('stays in range and covers every value', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 2000; i++) {
      const value = randomInt(10);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(10);
      seen.add(value);
    }
    expect(seen.size).toBe(10);
  });

  it('rejects biased draws above the largest multiple of the range', () => {
    // For n = 3, 2^32 % 3 = 1, so the single value 2^32 - 1 must be redrawn.
    const values = [2 ** 32 - 1, 5];
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(
      <T extends ArrayBufferView | null>(array: T): T => {
        (array as unknown as Uint32Array)[0] = values.shift()!;
        return array;
      },
    );
    expect(randomInt(3)).toBe(5 % 3);
    expect(values).toHaveLength(0);
  });
});

describe('entropyBits', () => {
  it('reflects length and alphabet size', () => {
    expect(entropyBits({ length: 20, numbers: false, symbols: false })).toBe(
      Math.floor(20 * Math.log2(52)),
    );
    expect(entropyBits({ length: 20, numbers: true, symbols: true })).toBeGreaterThan(120);
  });
});
