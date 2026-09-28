import { keyhole } from '../shared/emblem';

/**
 * The in-page prompt, rendered in a closed shadow root so page scripts can't
 * reach into it via `element.shadowRoot`, and page CSS can't restyle it.
 * All text is set with textContent, never innerHTML.
 */

export interface PromptAction {
  label: string;
  primary?: boolean;
  onClick: () => void;
}

export interface PromptContent {
  message: string;
  detail?: string;
  /** Optional choice between several saved logins. */
  choices?: { value: string; label: string }[];
  actions: PromptAction[];
}

const PROMPT_WIDTH_PX = 320;
/** Gap between the anchor field and the prompt beside it. */
const SIDE_GAP_PX = 12;
/** Gap between the anchor field and the prompt below it. */
const BELOW_GAP_PX = 8;

// Uses system serif/sans faces: loading the extension's bundled
// fonts here would mean exposing them to every page (web_accessible_resources),
// which also lets pages fingerprint the extension.
const STYLES = `
  :host { all: initial; }
  .prompt {
    position: fixed; top: 14px; right: 14px; z-index: 2147483647;
    width: ${PROMPT_WIDTH_PX}px; max-width: calc(100vw - 28px);
    padding: 14px 16px 14px;
    background: #1c2533; color: #e9e2d0;
    border: 1px solid rgb(52 80 111 / 70%);
    border-radius: 4px;
    box-shadow: 0 12px 32px rgb(0 0 0 / 45%);
    font: 14px/1.5 'Hiragino Sans', 'Yu Gothic UI', 'Yu Gothic', system-ui, sans-serif;
    color-scheme: dark;
    animation: rise 180ms ease-out both;
  }
  /* Gold seam along the top edge. */
  .prompt::before {
    content: ''; position: absolute; left: 0; right: 0; top: -1px; height: 2px;
    background: linear-gradient(90deg, transparent, #c9a45c 20%, #e0be78 50%, rgb(201 164 92 / 35%) 72%, transparent);
  }
  .head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .seal {
    display: grid; place-items: center; flex: none;
    width: 26px; height: 26px; border-radius: 3px;
    background: #c8553d; color: #1c2533;
  }
  .seal-icon { width: 10px; height: 12px; }
  .title { font: 700 15px/1.35 'Hiragino Mincho ProN', 'Yu Mincho', Georgia, serif; }
  .detail { color: #9d998f; font-size: 13px; margin: 0 0 12px 36px; word-break: break-all; }
  select {
    display: block; width: calc(100% - 36px); margin: 0 0 12px 36px;
    font: inherit; color: #e9e2d0; background: #141a24;
    border: 1px solid rgb(52 80 111 / 70%); border-radius: 3px; padding: 6px 8px;
  }
  .actions { display: flex; gap: 8px; justify-content: flex-end; }
  button {
    font: inherit; font-weight: 500; cursor: pointer;
    padding: 5px 12px; border-radius: 3px;
    color: #9d998f; background: transparent; border: 1px solid transparent;
  }
  button:hover { color: #e9e2d0; background: rgb(233 226 208 / 6%); }
  button.primary { background: #c9a45c; border-color: #c9a45c; color: #141a24; }
  button.primary:hover { background: #e0be78; border-color: #e0be78; }
  button:focus-visible, select:focus-visible { outline: 2px solid #c9a45c; outline-offset: 2px; }
  @keyframes rise { from { opacity: 0; transform: translateY(-6px); } }
  @media (prefers-reduced-motion: reduce) { .prompt { animation: none; } }
`;

export class Prompt {
  private host: HTMLElement | null = null;
  private root: ShadowRoot | null = null;
  private selected: string | null = null;
  private box: HTMLElement | null = null;
  private anchor: HTMLElement | null = null;
  private readonly reposition = () => this.position();

  /** Value of the selected choice, if the prompt offered choices. */
  get selection(): string | null {
    return this.selected;
  }

  /**
   * Shows the prompt next to `anchor` (the field it's about), or in the
   * top-right corner without one.
   */
  show(content: PromptContent, anchor?: HTMLElement | null): void {
    this.hide();
    this.host = document.createElement('vaultx-prompt');
    this.root = this.host.attachShadow({ mode: 'closed' });
    this.applyStyles(this.root);

    const box = el('div', 'prompt');
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-label', 'VaultX');
    const head = el('div', 'head');
    const seal = el('span', 'seal');
    seal.append(keyhole('seal-icon'));
    head.append(seal, el('div', 'title', content.message));
    box.append(head);
    if (content.detail) box.append(el('div', 'detail', content.detail));

    this.selected = content.choices?.[0]?.value ?? null;
    if (content.choices && content.choices.length > 1) {
      const select = document.createElement('select');
      select.setAttribute('aria-label', 'Choose login');
      for (const choice of content.choices) {
        const option = document.createElement('option');
        option.value = choice.value;
        option.textContent = choice.label;
        select.append(option);
      }
      select.addEventListener('change', () => {
        this.selected = select.value;
      });
      box.append(select);
    }

    const actions = el('div', 'actions');
    for (const action of content.actions) {
      const button = el('button', action.primary ? 'primary' : '', action.label);
      button.addEventListener('click', (event) => {
        // Ignore synthetic clicks dispatched by page scripts; only a real
        // user gesture may trigger a fill or save.
        if (!event.isTrusted) return;
        action.onClick();
      });
      actions.append(button);
    }
    box.append(actions);
    this.root.append(box);
    document.documentElement.append(this.host);

    this.box = box;
    if (anchor) {
      this.anchor = anchor;
      this.position();
      // Capture phase, so scrolling any container (scroll doesn't bubble) moves it too.
      window.addEventListener('scroll', this.reposition, { capture: true, passive: true });
      window.addEventListener('resize', this.reposition, { passive: true });
    }
  }

  hide(): void {
    window.removeEventListener('scroll', this.reposition, { capture: true });
    window.removeEventListener('resize', this.reposition);
    this.host?.remove();
    this.host = null;
    this.root = null;
    this.box = null;
    this.anchor = null;
  }

  /** Beside the anchor if it fits in the viewport, otherwise underneath it. */
  private position(): void {
    if (!this.box || !this.anchor) return;
    const rect = this.anchor.getBoundingClientRect();
    const fitsBeside = rect.right + SIDE_GAP_PX + PROMPT_WIDTH_PX <= window.innerWidth;
    const { style } = this.box;
    style.right = 'auto';
    style.left = `${fitsBeside ? rect.right + SIDE_GAP_PX : rect.left}px`;
    style.top = `${fitsBeside ? rect.top : rect.bottom + BELOW_GAP_PX}px`;
  }

  private applyStyles(root: ShadowRoot): void {
    // Constructable stylesheets aren't subject to the page's CSP style-src.
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(STYLES);
      root.adoptedStyleSheets = [sheet];
    } catch {
      root.append(el('style', '', STYLES));
    }
  }
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}
