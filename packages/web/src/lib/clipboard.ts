/**
 * Copies secrets to the clipboard and clears them again shortly after.
 *
 * Browsers only let a page read the clipboard with a permission prompt, so
 * we can't check whether it still holds our secret. Instead the clear is
 * cancelled if the user copies something else in this page, and otherwise
 * happens unconditionally (it may wipe something copied in another app in
 * the meantime). If the page isn't focused when the timer fires, the browser
 * refuses the write, so the clear is retried when the page regains focus.
 */

export const CLIPBOARD_CLEAR_MS = 30_000;

let timer: ReturnType<typeof setTimeout> | null = null;
let awaitingFocus = false;

function cancel(): void {
  if (timer !== null) clearTimeout(timer);
  timer = null;
  if (awaitingFocus) window.removeEventListener('focus', retryOnFocus);
  awaitingFocus = false;
  document.removeEventListener('copy', cancel);
}

function retryOnFocus(): void {
  void clear();
}

async function clear(): Promise<void> {
  if (timer !== null) clearTimeout(timer);
  timer = null;
  try {
    await navigator.clipboard.writeText('');
    cancel();
  } catch {
    if (!awaitingFocus) window.addEventListener('focus', retryOnFocus);
    awaitingFocus = true;
  }
}

/** Copies `secret` and schedules it to be cleared from the clipboard. */
export async function copySecret(secret: string, clearAfterMs = CLIPBOARD_CLEAR_MS): Promise<void> {
  cancel();
  await navigator.clipboard.writeText(secret);
  timer = setTimeout(() => void clear(), clearAfterMs);
  // Our own writeText doesn't fire 'copy'; a user copy (Ctrl+C) does.
  document.addEventListener('copy', cancel);
}

/** Clears a pending secret right away, e.g. when the vault locks. */
export function clearCopiedSecretNow(): void {
  if (timer !== null || awaitingFocus) void clear();
}
