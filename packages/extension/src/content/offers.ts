/**
 * Offers to fill cards and identities on checkout and address forms. Unlike
 * logins they aren't tied to a site, so any secure page with such a form gets
 * an offer: the page only ever learns what the user picks, after a click.
 */
import type {
  ContentRequest,
  FillFormMessage,
  FormFill,
  FormItemSummary,
  FormKind,
  Response,
} from '../shared/messages';
import { findCardForm, findIdentityForm } from './detectForms';
import { fillCardForm, fillIdentityForm } from './fillForms';
import type { Prompt } from './ui';

interface Deps {
  prompt: Prompt;
  send: <T>(request: ContentRequest) => Promise<Response<T>>;
  /** Hides the prompt and stops offering anything more on this page. */
  dismiss: () => void;
}

const TEXT: Record<FormKind, { offer: string; choose: string; missing: string }> = {
  card: { offer: 'Fill card?', choose: 'Choose card', missing: 'There’s no card form here.' },
  identity: {
    offer: 'Fill address?',
    choose: 'Choose identity',
    missing: 'There’s no address form here.',
  },
};

/**
 * Finds the form for `kind` now (pages re-render) and fills it. False if
 * there's no such form any more; a form whose fields were all typed in
 * already counts as filled.
 */
function fillForm(fill: FormFill, overwrite: boolean): boolean {
  if (fill.kind === 'card') {
    const form = findCardForm(document);
    if (form) fillCardForm(form, fill.values, { overwrite });
    return form !== null;
  }
  const form = findIdentityForm(document);
  if (form) fillIdentityForm(form, fill.values, { overwrite });
  return form !== null;
}

export function createFormOffers({ prompt, send, dismiss }: Deps) {
  const offered = new Set<FormKind>();

  function couldNotFill(detail: string): void {
    prompt.show({
      message: 'Could not fill',
      detail,
      actions: [{ label: 'Close', onClick: dismiss }],
    });
  }

  async function fill(kind: FormKind, itemId: string): Promise<void> {
    const response = await send<FormFill>({ type: 'fillFormItem', kind, itemId });
    if (!response.ok) return couldNotFill(response.error);
    if (!fillForm(response.data, false)) return couldNotFill(TEXT[kind].missing);
    prompt.hide();
  }

  async function show(kind: FormKind, anchor: HTMLElement, nameOnly: boolean): Promise<boolean> {
    offered.add(kind);
    const response = await send<FormItemSummary[]>({ type: 'getFormItems', kind });
    // Locked, or nothing saved: say nothing (the popup can unlock and fill).
    if (!response.ok || response.data.length === 0) return false;
    const items = response.data;
    prompt.show(
      {
        message: nameOnly ? 'Fill name on card?' : TEXT[kind].offer,
        detail: items.length === 1 ? items[0]!.label : `${items.length} saved`,
        choices: items.map((item) => ({ value: item.id, label: item.label })),
        choiceLabel: TEXT[kind].choose,
        actions: [
          { label: 'Not now', onClick: dismiss },
          {
            label: 'Fill',
            primary: true,
            onClick: () => void fill(kind, prompt.selection ?? items[0]!.id),
          },
        ],
      },
      anchor,
    );
    return true;
  }

  return {
    /** Offers a card, else an identity, if the page has a form for one. True if it showed a prompt. */
    async offer(): Promise<boolean> {
      const card = offered.has('card') ? null : findCardForm(document);
      if (card) {
        const nameOnly = !card.fields.number;
        if (await show('card', card.anchor, nameOnly)) return true;
      }
      const identity = offered.has('identity') ? null : findIdentityForm(document);
      if (identity) return show('identity', identity.anchor, false);
      return false;
    },

    /** The user asked for `kind` (shortcut or menu): offer it even if already offered. */
    async offerKind(kind: FormKind): Promise<void> {
      const form = kind === 'card' ? findCardForm(document) : findIdentityForm(document);
      if (!form) return couldNotFill(TEXT[kind].missing);
      const nameOnly = kind === 'card' && !(form.fields as { number?: unknown }).number;
      if (!(await show(kind, form.anchor, nameOnly))) couldNotFill('Nothing saved to fill here.');
    },

    /** "Fill in this tab" from the popup: the user picked the item, so fields are overwritten. */
    fillFromPopup(message: FillFormMessage): void {
      if (!fillForm(message, true)) couldNotFill(TEXT[message.kind].missing);
      else prompt.hide();
    },
  };
}
