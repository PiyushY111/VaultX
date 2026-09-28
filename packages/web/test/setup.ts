import '@testing-library/jest-dom/vitest';
import { TextEncoder as NodeTextEncoder } from 'node:util';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Vitest's jsdom environment swaps the global Uint8Array for jsdom's, but
// TextEncoder still returns Node-realm arrays, which then fail libsodium's
// `instanceof Uint8Array` checks. Browsers have a single realm; mirror that.
class SameRealmTextEncoder extends NodeTextEncoder {
  override encode(input?: string): Uint8Array<ArrayBuffer> {
    return new Uint8Array(super.encode(input));
  }
}
Object.assign(globalThis, { TextEncoder: SameRealmTextEncoder });

// Node 25 ships its own experimental localStorage global, which shadows
// jsdom's and throws without --localstorage-file. (Tests in the node
// environment, like test/build-output.test.ts, have no jsdom.)
const { jsdom } = globalThis as unknown as { jsdom?: { window: Window } };
if (jsdom) {
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: jsdom.window.localStorage,
  });
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true,
    value: jsdom.window.sessionStorage,
  });
}

afterEach(() => {
  cleanup();
});
