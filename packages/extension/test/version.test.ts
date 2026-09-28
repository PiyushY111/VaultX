import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const read = async (path: string) =>
  JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8')) as { version: string };

describe('versions', () => {
  it('keeps manifest.json in step with package.json and the repository version', async () => {
    const [manifest, pkg, root] = await Promise.all([
      read('../manifest.json'),
      read('../package.json'),
      read('../../../package.json'),
    ]);
    expect(manifest.version).toBe(pkg.version);
    expect(pkg.version).toBe(root.version);
  });

  it('uses the same version in every workspace', async () => {
    const versions = await Promise.all(
      ['crypto', 'server', 'web', 'extension'].map(
        async (name) => (await read(`../../${name}/package.json`)).version,
      ),
    );
    expect(new Set(versions)).toEqual(new Set([(await read('../../../package.json')).version]));
  });
});
