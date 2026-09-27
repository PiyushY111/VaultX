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
