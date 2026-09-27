// The product's emblem: a keyhole inside a double ring. Built with DOM APIs
// (never innerHTML) so it can be used in the popup and the in-page prompt.

const SVG_NS = 'http://www.w3.org/2000/svg';
const KEYHOLE = 'M50 27a11 11 0 0 1 6.5 19.9L60 72H40l3.5-25.1A11 11 0 0 1 50 27z';

function svg(viewBox: string, className: string): SVGSVGElement {
  const element = document.createElementNS(SVG_NS, 'svg');
  element.setAttribute('viewBox', viewBox);
  element.setAttribute('class', className);
  element.setAttribute('aria-hidden', 'true');
  element.setAttribute('focusable', 'false');
  return element;
}

function node(tag: string, attributes: Record<string, string>): SVGElement {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  return element;
}

export function emblem(className: string): SVGSVGElement {
  const element = svg('0 0 100 100', className);
  element.append(
    node('circle', {
      cx: '50',
      cy: '50',
      r: '46',
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': '3',
    }),
    node('circle', {
      cx: '50',
      cy: '50',
      r: '39',
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': '1.25',
      opacity: '0.55',
    }),
    node('path', { d: KEYHOLE, fill: 'currentColor' }),
  );
  return element;
}

/** Just the keyhole, for small icons. */
export function keyhole(className: string): SVGSVGElement {
  const element = svg('26 22 48 56', className);
  element.append(node('path', { d: KEYHOLE, fill: 'currentColor' }));
  return element;
}
