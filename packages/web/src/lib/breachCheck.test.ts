import { describe, expect, it, vi } from 'vitest';
import { HIBP_RANGE_URL, checkBreaches, sha1Hex } from './breachCheck';

describe('sha1Hex', () => {
  it('matches the known SHA-1 of "password"', async () => {
    expect(await sha1Hex('password')).toBe('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8');
  });
});

describe('checkBreaches', () => {
  // "password" → 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
  const fakeFetch = vi.fn(async (input: RequestInfo | URL) => {
    const prefix = String(input).slice(-5);
    const body =
      prefix === '5BAA6'
        ? '1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000A:0'
        : '0000000000000000000000000000000000A:0';
    return new Response(body, { status: 200 });
  }) as unknown as typeof fetch;

  it('sends only a 5-character hash prefix and compares locally', async () => {
    const result = await checkBreaches(['password', 'orbit-lantern-quilt-58', 'password'], {
      fetch: fakeFetch,
    });
    expect(result.get('password')).toBe(3861493);
    expect(result.get('orbit-lantern-quilt-58')).toBe(0);
    const urls = (fakeFetch as unknown as { mock: { calls: [string][] } }).mock.calls.map(([url]) =>
      String(url),
    );
    expect(urls).toHaveLength(2); // deduplicated
    for (const url of urls) {
      expect(url).toMatch(new RegExp(`^${HIBP_RANGE_URL}[0-9A-F]{5}$`));
      expect(url.slice(HIBP_RANGE_URL.length)).toHaveLength(5);
    }
  });

  it('fails clearly when the service is unavailable', async () => {
    const down = (async () => new Response('', { status: 503 })) as unknown as typeof fetch;
    await expect(checkBreaches(['x'], { fetch: down })).rejects.toThrow(/HTTP 503/);
  });
});
