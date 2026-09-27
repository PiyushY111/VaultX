import { describe, expect, it } from 'vitest';
import { parseItem as webParse, serializeItem as webSerialize } from '../../web/src/vault/items';
import { parseItem, serializeItem } from '../src/background/items';

// Items saved by the extension must open in the web vault and vice versa.
describe('item format is shared with packages/web', () => {
  const data = { site: 'github.com', username: 'octocat', password: 'p@ss "x"', notes: 'n\nm' };

  it('serializes identically', () => {
    expect(serializeItem(data)).toBe(webSerialize(data));
  });

  it('round-trips across packages', () => {
    expect(webParse(serializeItem(data))).toEqual(data);
    expect(parseItem(webSerialize(data))).toEqual(data);
  });
});
