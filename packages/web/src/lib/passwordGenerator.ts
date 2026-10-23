export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>/?~';

export interface GeneratorOptions {
  length: number;
  numbers: boolean;
  symbols: boolean;
}

export const DEFAULT_GENERATOR_OPTIONS: GeneratorOptions = {
  length: 20,
  numbers: true,
  symbols: true,
};

function characterClasses({ numbers, symbols }: GeneratorOptions): string[] {
  return [LOWERCASE, UPPERCASE, ...(numbers ? [NUMBERS] : []), ...(symbols ? [SYMBOLS] : [])];
}

/** Uniform integer in [0, maxExclusive) from the Web Crypto CSPRNG, via rejection sampling (no modulo bias). */
export function randomInt(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 2 ** 32) {
    throw new RangeError('maxExclusive must be an integer in [1, 2^32]');
  }
  const limit = 2 ** 32 - (2 ** 32 % maxExclusive);
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    const value = buffer[0]!;
    if (value < limit) return value % maxExclusive;
  }
}

/**
 * Generates a password with each character drawn uniformly from the enabled
 * classes, guaranteeing at least one character from each. Candidates missing
 * a class are discarded and redrawn, which keeps the distribution uniform over
 * all valid passwords.
 */
export function generatePassword(options: GeneratorOptions): string {
  const { length } = options;
  if (!Number.isInteger(length) || length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(
      `length must be an integer from ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH}`,
    );
  }
  const classes = characterClasses(options);
  const alphabet = classes.join('');
  for (;;) {
    let password = '';
    for (let i = 0; i < length; i++) password += alphabet[randomInt(alphabet.length)];
    if (classes.every((chars) => [...password].some((char) => chars.includes(char))))
      return password;
  }
}

/** Approximate strength in bits (upper bound; ignores the at-least-one-of-each constraint). */
export function entropyBits(options: GeneratorOptions): number {
  return Math.floor(options.length * Math.log2(characterClasses(options).join('').length));
}

export const MIN_PASSPHRASE_WORDS = 4;
export const MAX_PASSPHRASE_WORDS = 12;
export const PASSPHRASE_SEPARATORS = ['-', '.', '_', ' '] as const;
export type PassphraseSeparator = (typeof PASSPHRASE_SEPARATORS)[number];

export interface PassphraseOptions {
  words: number;
  separator: PassphraseSeparator;
  /** Capitalize one randomly chosen word. */
  capitalize: boolean;
  /** Append one random digit to one randomly chosen word. */
  includeNumber: boolean;
}

/** Six EFF words plus a capital and a digit: about 86 bits. */
export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  words: 6,
  separator: '-',
  capitalize: true,
  includeNumber: true,
};

/**
 * Generates a passphrase of words drawn uniformly (with repetition) from
 * `wordlist`. The list is a parameter so callers can load it lazily (see
 * lib/wordlist); its words must not contain any of the separators.
 */
export function generatePassphrase(
  options: PassphraseOptions,
  wordlist: readonly string[],
): string {
  const { words, separator, capitalize, includeNumber } = options;
  if (!Number.isInteger(words) || words < MIN_PASSPHRASE_WORDS || words > MAX_PASSPHRASE_WORDS) {
    throw new RangeError(
      `words must be an integer from ${MIN_PASSPHRASE_WORDS} to ${MAX_PASSPHRASE_WORDS}`,
    );
  }
  if (!PASSPHRASE_SEPARATORS.includes(separator)) throw new RangeError('Unknown separator');
  if (wordlist.length < 2) throw new RangeError('The word list needs at least two words');

  const picked = Array.from({ length: words }, () => wordlist[randomInt(wordlist.length)]!);
  const capitalized = capitalize ? randomInt(words) : -1;
  const numbered = includeNumber ? randomInt(words) : -1;
  return picked
    .map((word, index) => {
      const cased = index === capitalized ? word[0]!.toUpperCase() + word.slice(1) : word;
      return index === numbered ? `${cased}${randomInt(10)}` : cased;
    })
    .join(separator);
}

/**
 * Strength in bits: the words, plus which word is capitalized, plus the digit
 * and which word it's on. The separator is the user's choice, so it adds
 * nothing.
 */
export function passphraseEntropyBits(options: PassphraseOptions, wordlistSize: number): number {
  const { words, capitalize, includeNumber } = options;
  return Math.floor(
    words * Math.log2(wordlistSize) +
      (capitalize ? Math.log2(words) : 0) +
      (includeNumber ? Math.log2(10) + Math.log2(words) : 0),
  );
}
