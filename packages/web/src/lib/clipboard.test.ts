import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CLIPBOARD_CLEAR_MS, clearCopiedSecretNow, copySecret } from './clipboard';

let clipboard: string;
let writable: boolean;

beforeEach(() => {
  vi.useFakeTimers();
  clipboard = '';
  writable = true;
  vi.stubGlobal('navigator', {
    clipboard: {
      writeText: vi.fn(async (text: string) => {
        if (!writable) throw new DOMException('Document is not focused', 'NotAllowedError');
        clipboard = text;
      }),
    },
  });
});

afterEach(() => {
  clearCopiedSecretNow();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('copySecret', () => {
  it('clears the clipboard after 30 seconds', async () => {
    await copySecret('hunter2');
    expect(clipboard).toBe('hunter2');
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS - 1);
    expect(clipboard).toBe('hunter2');
    await vi.advanceTimersByTimeAsync(1);
    expect(clipboard).toBe('');
  });

  it('restarts the timer when another secret is copied', async () => {
    await copySecret('first');
    await vi.advanceTimersByTimeAsync(20_000);
    await copySecret('second');
    await vi.advanceTimersByTimeAsync(20_000);
    expect(clipboard).toBe('second');
    await vi.advanceTimersByTimeAsync(10_000);
    expect(clipboard).toBe('');
  });

  it('leaves the clipboard alone once the user copies something else in the page', async () => {
    await copySecret('hunter2');
    document.dispatchEvent(new Event('copy'));
    clipboard = 'something the user copied';
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
    expect(clipboard).toBe('something the user copied');
  });

  it('retries when the page regains focus if the browser refused the clear', async () => {
    await copySecret('hunter2');
    writable = false;
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
    expect(clipboard).toBe('hunter2');
    writable = true;
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clipboard).toBe('');
  });

  it('clears right away when asked (on lock)', async () => {
    await copySecret('hunter2');
    clearCopiedSecretNow();
    await vi.advanceTimersByTimeAsync(0);
    expect(clipboard).toBe('');
  });
});
