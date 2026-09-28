// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Prompt, type PromptContent } from '../src/content/ui';

const CONTENT: PromptContent = { message: 'Fill saved login?', actions: [] };

/** The prompt's shadow root is closed; capture it as it's created. */
function captureRoots(): ShadowRoot[] {
  const roots: ShadowRoot[] = [];
  const original = Element.prototype.attachShadow;
  vi.spyOn(Element.prototype, 'attachShadow').mockImplementation(function (
    this: Element,
    init: ShadowRootInit,
  ) {
    const root = original.call(this, init);
    roots.push(root);
    return root;
  });
  return roots;
}

function anchorAt(rect: { left: number; top: number; width: number; height: number }) {
  const input = document.createElement('input');
  document.body.append(input);
  const current = { ...rect };
  input.getBoundingClientRect = () =>
    ({
      ...current,
      x: current.left,
      y: current.top,
      right: current.left + current.width,
      bottom: current.top + current.height,
      toJSON: () => ({}),
    }) as DOMRect;
  return { input, move: (next: Partial<typeof rect>) => Object.assign(current, next) };
}

const box = (roots: ShadowRoot[]) => roots.at(-1)!.querySelector<HTMLElement>('.prompt')!;

describe('Prompt positioning', () => {
  let roots: ShadowRoot[];

  beforeEach(() => {
    roots = captureRoots();
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 1280 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.replaceChildren();
    document.querySelectorAll('vaultx-prompt').forEach((node) => node.remove());
  });

  it('keeps the top-right corner without an anchor', () => {
    new Prompt().show(CONTENT);
    expect(box(roots).style.top).toBe('');
    expect(box(roots).style.left).toBe('');
  });

  it('sits to the right of the anchor when it fits', () => {
    const { input } = anchorAt({ left: 100, top: 200, width: 240, height: 36 });
    new Prompt().show(CONTENT, input);
    expect(box(roots).style.left).toBe('352px'); // 100 + 240 + 12
    expect(box(roots).style.top).toBe('200px');
    expect(box(roots).style.right).toBe('auto');
  });

  it('drops underneath the anchor when there is no room on the right', () => {
    const { input } = anchorAt({ left: 900, top: 200, width: 240, height: 36 });
    new Prompt().show(CONTENT, input); // 900 + 240 + 12 + 320 > 1280
    expect(box(roots).style.left).toBe('900px');
    expect(box(roots).style.top).toBe('244px'); // 200 + 36 + 8
  });

  it('follows the anchor on scroll and resize while shown', () => {
    const { input, move } = anchorAt({ left: 100, top: 200, width: 240, height: 36 });
    new Prompt().show(CONTENT, input);
    move({ top: 50 });
    window.dispatchEvent(new Event('scroll'));
    expect(box(roots).style.top).toBe('50px');

    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 600 });
    window.dispatchEvent(new Event('resize'));
    expect(box(roots).style.left).toBe('100px');
    expect(box(roots).style.top).toBe('94px'); // 50 + 36 + 8
  });

  it('follows the anchor when a scrollable container scrolls', () => {
    const { input, move } = anchorAt({ left: 100, top: 200, width: 240, height: 36 });
    new Prompt().show(CONTENT, input);
    move({ top: 120 });
    document.body.dispatchEvent(new Event('scroll')); // scroll doesn't bubble
    expect(box(roots).style.top).toBe('120px');
  });

  it('stops listening once hidden', () => {
    const removed = vi.spyOn(window, 'removeEventListener');
    const { input } = anchorAt({ left: 100, top: 200, width: 240, height: 36 });
    const prompt = new Prompt();
    prompt.show(CONTENT, input);
    prompt.hide();
    const types = removed.mock.calls.map(([type]) => type);
    expect(types).toContain('scroll');
    expect(types).toContain('resize');
  });

  it('stops following the old anchor when shown again without one', () => {
    const { input, move } = anchorAt({ left: 100, top: 200, width: 240, height: 36 });
    const prompt = new Prompt();
    prompt.show(CONTENT, input);
    prompt.show(CONTENT);
    move({ top: 10 });
    window.dispatchEvent(new Event('scroll'));
    expect(box(roots).style.top).toBe('');
  });
});
