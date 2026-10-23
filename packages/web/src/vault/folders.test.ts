import { describe, expect, it } from 'vitest';
import {
  buildFolderTree,
  folderPaths,
  isInFolder,
  moveFolder,
  parentFolder,
  withFolder,
} from './folders';
import type { VaultItem } from './items';

let n = 0;
const item = (folder?: string, extra: Partial<VaultItem> = {}): VaultItem => ({
  id: `id-${n++}`,
  revision: 1,
  site: `site-${n}.example.com`,
  username: '',
  password: '',
  notes: '',
  createdAt: '',
  updatedAt: '',
  ...(folder && { folder }),
  ...extra,
});

describe('buildFolderTree', () => {
  it('nests folders, sorted, counting items in subfolders too', () => {
    const tree = buildFolderTree([
      item('Work/Servers'),
      item('Work/Servers'),
      item('Work'),
      item('Personal'),
      item(),
    ]);
    expect(tree).toEqual([
      { name: 'Personal', path: 'Personal', count: 1, children: [] },
      {
        name: 'Work',
        path: 'Work',
        count: 3,
        children: [{ name: 'Servers', path: 'Work/Servers', count: 2, children: [] }],
      },
    ]);
  });

  it('merges folders that differ only in case, under the first spelling seen', () => {
    const tree = buildFolderTree([item('work/Servers'), item('Work/servers'), item('WORK')]);
    expect(tree).toEqual([
      {
        name: 'work',
        path: 'work',
        count: 3,
        children: [{ name: 'Servers', path: 'work/Servers', count: 2, children: [] }],
      },
    ]);
  });

  it('shows a parent that holds only subfolders', () => {
    expect(buildFolderTree([item('A/B/C')])).toMatchObject([
      { path: 'A', count: 1, children: [{ path: 'A/B', children: [{ path: 'A/B/C' }] }] },
    ]);
  });
});

describe('isInFolder', () => {
  it('includes subfolders unless told not to, ignoring case', () => {
    expect(isInFolder(item('Work/Servers'), 'work')).toBe(true);
    expect(isInFolder(item('Work/Servers'), 'Work', false)).toBe(false);
    expect(isInFolder(item('Work'), 'Work', false)).toBe(true);
  });

  it('doesn’t match a folder that only starts with the same letters', () => {
    expect(isInFolder(item('Workshop'), 'Work')).toBe(false);
    expect(isInFolder(item(), 'Work')).toBe(false);
  });
});

describe('moveFolder', () => {
  it('renames a folder and everything under it, leaving look-alikes alone', () => {
    const work = item('Work');
    const servers = item('Work/Servers');
    const workshop = item('Workshop');
    const changes = moveFolder([work, servers, workshop, item()], 'Work', 'Job');
    expect(changes.map(({ item: it, data }) => [it.id, data.folder])).toEqual([
      [work.id, 'Job'],
      [servers.id, 'Job/Servers'],
    ]);
  });

  it('moves a deleted folder’s items to its parent, or out of any folder', () => {
    const changes = moveFolder([item('A/B'), item('A/B/C')], 'A/B', parentFolder('A/B'));
    expect(changes.map(({ data }) => data.folder)).toEqual(['A', 'A/C']);

    const top = moveFolder([item('A'), item('A/C')], 'A', parentFolder('A'));
    expect(top[0]!.data).not.toHaveProperty('folder');
    expect(top[1]!.data.folder).toBe('C');
  });

  it('skips items that already end up where they are', () => {
    expect(moveFolder([item('Work')], 'Work', 'work')).toHaveLength(1);
    expect(moveFolder([item('Work')], 'Work', 'Work')).toEqual([]);
  });

  it('refuses a move that would nest too deeply', () => {
    expect(() => moveFolder([item('A/B/C')], 'A', 'X/Y/Z/W')).toThrow(RangeError);
  });

  it('keeps everything else about the item, including the trash', () => {
    const trashed = item('Work', { deletedAt: '2026-10-01T00:00:00.000Z', notes: 'n' });
    const [change] = moveFolder([trashed], 'Work', 'Job');
    expect(change!.data).toMatchObject({ notes: 'n', deletedAt: trashed.deletedAt, folder: 'Job' });
  });
});

describe('withFolder', () => {
  it('sets, normalizes or clears an item’s folder without changing the original', () => {
    const original = item('Work');
    expect(withFolder(original, ' Home / Bills ').folder).toBe('Home/Bills');
    expect(withFolder(original, '')).not.toHaveProperty('folder');
    expect(original.folder).toBe('Work');
  });
});

describe('folderPaths', () => {
  it('lists every folder, parents first', () => {
    const tree = buildFolderTree([item('Work/Servers'), item('Personal'), item('Work')]);
    expect(folderPaths(tree)).toEqual(['Personal', 'Work', 'Work/Servers']);
  });
});
