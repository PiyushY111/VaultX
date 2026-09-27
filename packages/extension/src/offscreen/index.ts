// Offscreen document: the MV3 service worker has no clipboard access, so it
// opens this page just long enough to clear a copied password.
import type { ClearClipboardMessage } from '../shared/messages';

const isClearRequest = (message: unknown): message is ClearClipboardMessage =>
  typeof message === 'object' &&
  message !== null &&
  (message as ClearClipboardMessage).target === 'offscreen' &&
  (message as ClearClipboardMessage).type === 'clearClipboard';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !isClearRequest(message)) return;
  // execCommand('copy') fires a copy event even with nothing selected, which
  // lets us replace the clipboard's contents with an empty string.
  const replace = (event: ClipboardEvent) => {
    event.clipboardData?.setData('text/plain', '');
    event.preventDefault();
  };
  document.addEventListener('copy', replace);
  const cleared = document.execCommand('copy');
  document.removeEventListener('copy', replace);
  sendResponse(cleared);
});
