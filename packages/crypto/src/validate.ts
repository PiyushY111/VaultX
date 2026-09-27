import { CryptoInputError } from './errors.js';

export function assertBytes(
  value: unknown,
  length: number,
  name: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new CryptoInputError(`${name} must be a Uint8Array`);
  }
  if (value.length !== length) {
    throw new CryptoInputError(`${name} must be ${length} bytes, got ${value.length}`);
  }
}
