/**
 * Seeded randomized ("fuzz") testing without a library. Every case gets its
 * own seed derived from FUZZ_SEED, the case name and its index, so a failure
 * report names a seed that reproduces it exactly:
 *
 *   FUZZ_SEED=<seed> FUZZ_RUNS=<n> npm test
 *
 * This file is duplicated in packages/{crypto,web,server}/test/fuzz.ts
 * (the packages don't share test code); keep the copies identical.
 */

export const FUZZ_SEED = Number(process.env.FUZZ_SEED ?? 0x5eed_2026);
export const FUZZ_RUNS = Number(process.env.FUZZ_RUNS ?? 300);

/** xorshift32: tiny, fast, and deterministic for a given seed (not for cryptography). */
export class Rng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0 || 0x9e3779b9;
  }

  next(): number {
    let x = this.state;
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    this.state = x >>> 0;
    return this.state;
  }

  /** 0 ≤ n < max */
  int(max: number): number {
    return max <= 0 ? 0 : this.next() % max;
  }

  bool(probability = 0.5): boolean {
    return this.next() / 0x1_0000_0000 < probability;
  }

  pick<T>(items: readonly T[]): T {
    return items[this.int(items.length)]!;
  }

  bytes(length: number): Uint8Array {
    return Uint8Array.from({ length }, () => this.int(256));
  }

  /** A string from `alphabet`, or from a mix of ASCII, control, and astral characters. */
  string(maxLength: number, alphabet?: string): string {
    const length = this.int(maxLength + 1);
    let out = '';
    for (let i = 0; i < length; i++) {
      if (alphabet) out += alphabet[this.int(alphabet.length)];
      else out += this.char();
    }
    return out;
  }

  char(): string {
    switch (this.int(6)) {
      case 0:
        return String.fromCharCode(this.int(32)); // control
      case 1:
        return this.pick(['"', ',', '\n', '\r', '\\', '=', '&', '%', '?', '#', ':', '/', '\u0000']);
      case 2:
        return String.fromCodePoint(0x80 + this.int(0x780)); // Latin-1+ and friends
      case 3:
        return String.fromCodePoint(0x1f300 + this.int(0x300)); // astral (surrogate pairs)
      case 4:
        return this.pick(['\ud800', '\udfff', '﻿', '​']); // lone surrogates, BOM, ZWSP
      default:
        return String.fromCharCode(0x20 + this.int(0x5f)); // printable ASCII
    }
  }

  /** A random JSON-compatible value, nested up to `depth`. */
  json(depth = 3): unknown {
    const kind = this.int(depth > 0 ? 8 : 6);
    switch (kind) {
      case 0:
        return null;
      case 1:
        return this.bool();
      case 2:
        return this.pick([0, -1, 1, 1.5, 2 ** 31, 2 ** 53, -(2 ** 53), 1e308, Number.MIN_VALUE]);
      case 3:
        return this.int(1000);
      case 4:
        return this.string(20);
      case 5:
        return this.pick(['', '0', 'true', 'null', '__proto__', 'constructor', 'A'.repeat(64)]);
      case 6:
        return Array.from({ length: this.int(5) }, () => this.json(depth - 1));
      default: {
        const value: Record<string, unknown> = {};
        for (let i = this.int(5); i > 0; i--) value[this.string(8)] = this.json(depth - 1);
        return value;
      }
    }
  }
}

/** Small random edits: insert, delete, replace or duplicate a slice. */
export function mutate(rng: Rng, input: string, edits = 1 + rng.int(4)): string {
  let text = input;
  for (let i = 0; i < edits; i++) {
    const at = rng.int(text.length + 1);
    switch (rng.int(4)) {
      case 0:
        text = text.slice(0, at) + rng.char() + text.slice(at);
        break;
      case 1:
        text = text.slice(0, at) + text.slice(at + 1 + rng.int(8));
        break;
      case 2:
        text = text.slice(0, at) + rng.char() + text.slice(at + 1);
        break;
      default:
        text = text.slice(0, at) + text.slice(at, at + rng.int(16)).repeat(2) + text.slice(at);
    }
  }
  return text;
}

function seedFor(name: string, index: number): number {
  let hash = FUZZ_SEED >>> 0;
  for (const char of `${name}#${index}`) hash = Math.imul(hash ^ char.charCodeAt(0), 0x01000193);
  return hash >>> 0;
}

/**
 * Runs `body` for FUZZ_RUNS seeded cases. Rethrows the first failure with
 * the case's seed and index in the message.
 */
export async function forEachCase(
  name: string,
  body: (rng: Rng, index: number) => void | Promise<void>,
  runs = FUZZ_RUNS,
): Promise<void> {
  for (let index = 0; index < runs; index++) {
    const seed = seedFor(name, index);
    try {
      await body(new Rng(seed), index);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `${name}: case ${index} failed (FUZZ_SEED=${FUZZ_SEED}, case seed ${seed}): ${detail}`,
        {
          cause: error,
        },
      );
    }
  }
}

type ErrorClass = abstract new (...args: never[]) => Error;

/**
 * Calls `fn`; passes if it returns, or throws an instance of one of
 * `allowed`, within `maxMs`. Anything else (TypeError, SyntaxError, a
 * DOMException, a hang) fails, with the input in the message.
 */
export async function expectTyped<T>(
  fn: () => T | Promise<T>,
  allowed: readonly ErrorClass[],
  input: unknown,
  maxMs = 2000,
): Promise<{ ok: true; value: T } | { ok: false; error: Error }> {
  const started = performance.now();
  let outcome: { ok: true; value: T } | { ok: false; error: Error };
  try {
    outcome = { ok: true, value: await fn() };
  } catch (error) {
    if (!allowed.some((type) => error instanceof type)) {
      const name = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
      throw new Error(`untyped error ${name} for input ${JSON.stringify(input)?.slice(0, 300)}`, {
        cause: error,
      });
    }
    outcome = { ok: false, error: error as Error };
  }
  const elapsed = performance.now() - started;
  if (elapsed > maxMs) {
    throw new Error(
      `took ${Math.round(elapsed)} ms (> ${maxMs}) for input ${JSON.stringify(input)?.slice(0, 300)}`,
    );
  }
  return outcome;
}
