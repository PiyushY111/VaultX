// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFormOffers } from '../src/content/offers';
import type { Prompt, PromptContent } from '../src/content/ui';
import type { ContentRequest, Response } from '../src/shared/messages';

const CHECKOUT = `<form>
  <input id="name" autocomplete="cc-name">
  <input id="num" autocomplete="cc-number">
  <input id="exp" autocomplete="cc-exp">
</form>`;
const CARD_FIELDS = { cardholder: 'Jane Doe', number: '4111111111114242', expiry: '03/27' };

/** A prompt that records what it's asked to show; actions are run by the test. */
function fakePrompt() {
  const shown: PromptContent[] = [];
  const prompt = {
    selection: null,
    show: vi.fn((content: PromptContent) => shown.push(content)),
    hide: vi.fn(),
  };
  return { prompt: prompt as unknown as Prompt, shown, hide: prompt.hide };
}

type Send = <T>(request: ContentRequest) => Promise<Response<T>>;

/** Answers each request type with a canned response; a mock, so calls can be checked. */
function fakeSend(answers: Partial<Record<ContentRequest['type'], Response<unknown>>>) {
  const send = vi.fn(
    async (request: ContentRequest): Promise<Response<unknown>> =>
      answers[request.type] ?? { ok: false, error: 'x' },
  );
  return send as typeof send & Send;
}

const value = (id: string) => (document.getElementById(id) as HTMLInputElement).value;
const action = (content: PromptContent, label: string) =>
  content.actions.find((a) => a.label === label)!;

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('card and identity offers', () => {
  it('offers a saved card on a checkout form and fills it after Fill', async () => {
    document.body.innerHTML = CHECKOUT;
    const { prompt, shown, hide } = fakePrompt();
    const send = fakeSend({
      getFormItems: { ok: true, data: [{ id: 'c1', label: 'Visa •••• 4242' }] },
      fillFormItem: { ok: true, data: { kind: 'card', host: 'shop.test', values: CARD_FIELDS } },
    });
    const offers = createFormOffers({ prompt, send, dismiss: vi.fn() });

    expect(await offers.offer()).toBe(true);
    expect(shown[0]).toMatchObject({ message: 'Fill card?', detail: 'Visa •••• 4242' });
    // Nothing is fetched or filled before the click.
    expect(send).toHaveBeenCalledTimes(1);
    expect(value('num')).toBe('');

    action(shown[0]!, 'Fill').onClick();
    await vi.waitFor(() => expect(value('num')).toBe('4111111111114242'));
    expect(send).toHaveBeenLastCalledWith({ type: 'fillFormItem', kind: 'card', itemId: 'c1' });
    expect(value('exp')).toBe('03/27');
    expect(hide).toHaveBeenCalled();
  });

  it('says nothing when the vault is locked or has no cards, and offers once per page', async () => {
    document.body.innerHTML = CHECKOUT;
    const { prompt } = fakePrompt();
    const send = fakeSend({ getFormItems: { ok: false, error: 'Vault is locked', locked: true } });
    const offers = createFormOffers({ prompt, send, dismiss: vi.fn() });
    expect(await offers.offer()).toBe(false);
    expect(prompt.show).not.toHaveBeenCalled();
    expect(await offers.offer()).toBe(false);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('offers nothing on a page without a checkout or address form', async () => {
    document.body.innerHTML = '<form><input name="q" type="search"></form>';
    const { prompt } = fakePrompt();
    const send = fakeSend({});
    expect(await createFormOffers({ prompt, send, dismiss: vi.fn() }).offer()).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('fills from the popup over what was typed, or says the form is gone', () => {
    document.body.innerHTML = CHECKOUT;
    (document.getElementById('name') as HTMLInputElement).value = 'typo';
    const { prompt, shown } = fakePrompt();
    const offers = createFormOffers({ prompt, send: fakeSend({}), dismiss: vi.fn() });
    offers.fillFromPopup({
      type: 'fillForm',
      kind: 'card',
      host: 'shop.test',
      values: CARD_FIELDS,
    });
    expect(value('name')).toBe('Jane Doe');

    document.body.innerHTML = '';
    offers.fillFromPopup({
      type: 'fillForm',
      kind: 'card',
      host: 'shop.test',
      values: CARD_FIELDS,
    });
    expect(shown.at(-1)).toMatchObject({ message: 'Could not fill' });
  });
});
