import { describe, expect, it } from 'vitest';
import { describeSession } from './sessionLabel';

describe('describeSession', () => {
  it.each([
    [
      'web',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
      'Web vault · Chrome on macOS',
    ],
    [
      'extension',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
      'Browser extension · Edge on Windows',
    ],
    [
      'web',
      'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
      'Web vault · Firefox on Linux',
    ],
    [
      'web',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
      'Web vault · Safari on iOS',
    ],
    [null, 'curl/8.0', 'Unknown app'],
    [null, null, 'Unknown app'],
  ] as const)('%s + %s → %s', (client, userAgent, expected) => {
    expect(describeSession({ client, user_agent: userAgent })).toBe(expected);
  });
});
