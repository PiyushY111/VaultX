/**
 * The popup's cards and identities: labels, "Fill in this tab", and copying a
 * card's number or security code (cleared from the clipboard later).
 */
import type { FormItemSummary } from '../shared/messages';
import { copyToClipboard, h, send } from './dom';

interface Listed {
  cards: FormItemSummary[];
  identities: FormItemSummary[];
}

/**
 * A section listing cards and identities, hidden until it has something to
 * show. `tabId` is the active http(s) tab, if any; `onError` shows a failed
 * request (and re-renders when the vault turns out to be locked).
 */
export function formsSection(
  tabId: number | null,
  status: HTMLElement,
  onError: (error: unknown) => void,
): HTMLElement {
  const section = h('section', { class: 'forms', 'aria-label': 'Cards and identities' });
  section.hidden = true;

  const copyField = (itemId: string, field: string, label: string) => {
    const button = h(
      'button',
      { type: 'button', class: 'btn btn-quiet', 'data-label': label },
      label,
    );
    button.title = 'Cleared from the clipboard after 30 seconds';
    button.addEventListener('click', async () => {
      try {
        const fields = await send<Record<string, string>>({ type: 'getFormItemFields', itemId });
        const value = field === 'number' ? (fields.number ?? '').replace(/\s/g, '') : fields[field];
        if (value) await copyToClipboard(value, button, status, true);
      } catch (error) {
        onError(error);
      }
    });
    return button;
  };

  const row = (item: FormItemSummary, isCard: boolean) =>
    h(
      'li',
      { class: 'entry', 'aria-label': item.label },
      h('div', { class: 'entry-body' }, h('strong', { class: 'entry-site' }, item.label)),
      h(
        'div',
        { class: 'entry-actions' },
        tabId !== null &&
          h(
            'button',
            {
              type: 'button',
              class: 'btn btn-primary',
              onclick: async () => {
                try {
                  await send({ type: 'fillTabWithForm', tabId, itemId: item.id });
                  window.close();
                } catch (error) {
                  onError(error);
                }
              },
            },
            'Fill in this tab',
          ),
        isCard && copyField(item.id, 'number', 'Copy number'),
        isCard && copyField(item.id, 'cvv', 'Copy code'),
      ),
    );

  void send<Listed>({ type: 'listFormItems' }).then(({ cards, identities }) => {
    if (cards.length === 0 && identities.length === 0) return;
    section.hidden = false;
    section.append(
      h('h2', { class: 'section-title' }, 'Cards and identities'),
      h(
        'ul',
        { class: 'ledger' },
        ...cards.map((card) => row(card, true)),
        ...identities.map((identity) => row(identity, false)),
      ),
    );
  }, onError);
  return section;
}
