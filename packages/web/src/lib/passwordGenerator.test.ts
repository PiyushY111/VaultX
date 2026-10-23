import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_PASSPHRASE_OPTIONS,
  MAX_PASSPHRASE_WORDS,
  MAX_PASSWORD_LENGTH,
  MIN_PASSPHRASE_WORDS,
  MIN_PASSWORD_LENGTH,
  PASSPHRASE_SEPARATORS,
  entropyBits,
  generatePassphrase,
  generatePassword,
  passphraseEntropyBits,
  randomInt,
  type PassphraseOptions,
} from './passwordGenerator';
import { MIN_MASTER_PASSWORD_SCORE, estimateStrength } from './passwordStrength';
import { EFF_LARGE } from './wordlist/effLarge';
import { loadWordlist } from './wordlist';

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

describe('EFF word list', () => {
  it('has the 7,772 unique, lowercase, unhyphenated words the entropy figures assume', () => {
    expect(EFF_LARGE).toHaveLength(7772);
    expect(new Set(EFF_LARGE).size).toBe(EFF_LARGE.length);
    for (const word of EFF_LARGE) expect(word).toMatch(/^[a-z]+$/);
    expect(EFF_LARGE[0]).toBe('abacus');
    expect(EFF_LARGE.at(-1)).toBe('zoom');
  });

  it('is loaded on demand, once', async () => {
    const first = loadWordlist();
    expect(await first).toBe(EFF_LARGE);
    expect(loadWordlist()).toBe(first);
  });
});

describe('generatePassphrase', () => {
  const plain: PassphraseOptions = {
    words: 6,
    separator: '-',
    capitalize: false,
    includeNumber: false,
  };

  it.each([MIN_PASSPHRASE_WORDS, 6, MAX_PASSPHRASE_WORDS])(
    'joins exactly %i words from the list',
    (words) => {
      const parts = generatePassphrase({ ...plain, words }, EFF_LARGE).split('-');
      expect(parts).toHaveLength(words);
      for (const part of parts) expect(EFF_LARGE).toContain(part);
    },
  );

  it.each(PASSPHRASE_SEPARATORS)('separates words with %j', (separator) => {
    const passphrase = generatePassphrase({ ...plain, separator }, ['ab', 'cd']);
    expect(passphrase.split(separator)).toHaveLength(6);
  });

  it('capitalizes exactly one word when asked', () => {
    for (let i = 0; i < 100; i++) {
      const words = generatePassphrase({ ...plain, capitalize: true }, EFF_LARGE).split('-');
      expect(words.filter((word) => /^[A-Z][a-z]+$/.test(word))).toHaveLength(1);
      expect(words.filter((word) => /^[a-z]+$/.test(word))).toHaveLength(5);
    }
  });

  it('appends exactly one digit to one word when asked', () => {
    for (let i = 0; i < 100; i++) {
      const passphrase = generatePassphrase({ ...plain, includeNumber: true }, EFF_LARGE);
      expect(passphrase.match(/[0-9]/g)).toHaveLength(1);
      expect(passphrase.split('-').filter((word) => /^[a-z]+[0-9]$/.test(word))).toHaveLength(1);
    }
  });

  it('picks words uniformly', () => {
    const counts = new Map<string, number>();
    const draws = 5000;
    for (let i = 0; i < draws; i++) {
      for (const word of generatePassphrase(plain, ['a', 'b', 'c', 'd']).split('-'))
        counts.set(word, (counts.get(word) ?? 0) + 1);
    }
    // 30,000 picks over 4 words: each near 7,500 (an off-by-one would starve one).
    expect([...counts.keys()].sort()).toEqual(['a', 'b', 'c', 'd']);
    for (const count of counts.values()) {
      expect(count / (draws * 6)).toBeGreaterThan(0.22);
      expect(count / (draws * 6)).toBeLessThan(0.28);
    }
  });

  it('uses crypto.getRandomValues, never Math.random', () => {
    const mathRandom = vi.spyOn(Math, 'random');
    const getRandomValues = vi.spyOn(crypto, 'getRandomValues');
    generatePassphrase(DEFAULT_PASSPHRASE_OPTIONS, EFF_LARGE);
    expect(mathRandom).not.toHaveBeenCalled();
    expect(getRandomValues).toHaveBeenCalled();
  });

  it.each([0, MIN_PASSPHRASE_WORDS - 1, MAX_PASSPHRASE_WORDS + 1, 5.5, Number.NaN])(
    'rejects %s words',
    (words) => {
      expect(() => generatePassphrase({ ...plain, words }, EFF_LARGE)).toThrow(RangeError);
    },
  );

  it('rejects an unknown separator and a list too short to choose from', () => {
    expect(() => generatePassphrase({ ...plain, separator: '' as never }, EFF_LARGE)).toThrow(
      RangeError,
    );
    expect(() => generatePassphrase(plain, ['only'])).toThrow(RangeError);
  });
});

describe('passphraseEntropyBits', () => {
  it('counts the words, plus which word is capitalized and which digit goes where', () => {
    const plain = { words: 6, separator: '-', capitalize: false, includeNumber: false } as const;
    expect(passphraseEntropyBits(plain, 7776)).toBe(77);
    expect(passphraseEntropyBits({ ...plain, capitalize: true }, 7776)).toBe(
      Math.floor(6 * Math.log2(7776) + Math.log2(6)),
    );
    expect(passphraseEntropyBits({ ...plain, includeNumber: true }, 7776)).toBe(
      Math.floor(6 * Math.log2(7776) + Math.log2(10) + Math.log2(6)),
    );
  });

  it('gives the default passphrase over 80 bits', () => {
    expect(passphraseEntropyBits(DEFAULT_PASSPHRASE_OPTIONS, EFF_LARGE.length)).toBeGreaterThan(80);
  });
});

describe('suggested master passphrases', () => {
  it('are rated strong enough to be a master password', async () => {
    for (let i = 0; i < 10; i++) {
      const passphrase = generatePassphrase(DEFAULT_PASSPHRASE_OPTIONS, EFF_LARGE);
      expect((await estimateStrength(passphrase, [])).score).toBeGreaterThanOrEqual(
        MIN_MASTER_PASSWORD_SCORE,
      );
    }
  });
});
