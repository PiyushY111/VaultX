/**
 * Small DOM and messaging helpers shared by the popup's modules. Everything is
 * rendered with textContent (via `h`), never innerHTML: item fields are
 * untrusted strings even in this trusted extension page.
 */
import type { PopupRequest, Response } from '../shared/messages';

export class RequestError extends Error {
  constructor(
    message: string,
    readonly locked: boolean,
    /** The password was right and a two-factor code is needed next. */
    readonly secondFactor = false,
    /** ...and it has to be a passkey or recovery code (the extension can't use passkeys). */
    readonly passkeyOnly = false,
  ) {
    super(message);
  }
}

export async function send<T>(request: PopupRequest): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T>;
  if (!response.ok) {
    throw new RequestError(
      response.error,
      response.locked === true,
      response.secondFactor === true,
      response.passkeyOnly === true,
    );
  }
  return response.data;
}

export type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<Record<string, string | boolean | ((event: Event) => void)>> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === 'function')
      element.addEventListener(key.replace(/^on/, '').toLowerCase(), value);
    else if (typeof value === 'boolean') element.toggleAttribute(key, value);
    else if (value !== undefined) element.setAttribute(key, value);
  }
  for (const child of children) {
    if (child) element.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return element;
}

/**
 * Copies `value`, briefly showing "Copied" on the button. A secret is also
 * cleared from the clipboard later by the background: the popup usually
 * closes before 30 seconds pass.
 */
export async function copyToClipboard(
  value: string,
  button: HTMLButtonElement,
  status: HTMLElement,
  secret = false,
): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    if (secret) await send({ type: 'scheduleClipboardClear' });
    button.textContent = 'Copied';
    setTimeout(() => (button.textContent = button.dataset.label ?? 'Copy'), 1500);
  } catch {
    status.textContent = 'Could not copy to the clipboard';
  }
}
