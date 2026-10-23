/**
 * The password last generated for the active tab from the right-click menu,
 * so it isn't lost if the site's form never triggers the save prompt. The
 * background keeps it for 15 minutes in memory-only storage.
 */
import type { GeneratedPassword } from '../shared/messages';
import { copyToClipboard, h, send } from './dom';

const minutesAgo = (createdAt: number) => {
  const minutes = Math.floor((Date.now() - createdAt) / 60_000);
  return minutes < 1 ? 'just now' : minutes === 1 ? '1 minute ago' : `${minutes} minutes ago`;
};

/**
 * A section for the tab's generated password, hidden unless there is one.
 * `onSave` opens the add-login form with the site and password filled in.
 */
export function generatedSection(
  tabId: number,
  status: HTMLElement,
  onSave: (host: string, password: string) => void,
  onError: (error: unknown) => void,
): HTMLElement {
  const section = h('section', { class: 'generated', 'aria-label': 'Generated password' });
  section.hidden = true;

  void send<GeneratedPassword | null>({ type: 'getGenerated', tabId }).then((record) => {
    if (!record) return;
    const secret = h('code', { class: 'secret' }, '••••••••');
    let revealed = false;
    const copy = h(
      'button',
      { type: 'button', class: 'btn btn-quiet', 'data-label': 'Copy' },
      'Copy',
    );
    copy.title = 'Cleared from the clipboard after 30 seconds';
    copy.addEventListener('click', () => void copyToClipboard(record.password, copy, status, true));
    section.hidden = false;
    section.append(
      h('h2', { class: 'section-title' }, 'Generated password'),
      h(
        'p',
        { class: 'muted' },
        `For ${record.host}, ${minutesAgo(record.createdAt)}. Kept for 15 minutes in case the site didn’t offer to save it.`,
      ),
      h(
        'div',
        { class: 'row' },
        secret,
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-quiet',
            onclick: (event: Event) => {
              revealed = !revealed;
              secret.textContent = revealed ? record.password : '••••••••';
              (event.target as HTMLButtonElement).textContent = revealed ? 'Hide' : 'Show';
            },
          },
          'Show',
        ),
        copy,
        h(
          'button',
          {
            type: 'button',
            class: 'btn btn-primary',
            onclick: () => onSave(record.host, record.password),
          },
          'Save as login',
        ),
      ),
    );
  }, onError);
  return section;
}
