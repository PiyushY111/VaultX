import { normalizeFolder, type VaultItemData } from '@password-manager/item-format';
// Types only, so there's no import cycle with items.ts at runtime.
import type { VaultItem } from './items';

/**
 * Folders exist only through the items in them: there's no separate folder
 * list to keep in sync, so an empty folder simply disappears. Paths compare
 * without case ("work" and "Work" are one folder, shown as first spelled).
 * Everything here is in memory; folder names never leave the encrypted items.
 */

export interface FolderNode {
  name: string;
  /** Full path, as {@link normalizeFolder} leaves it ("Work/Servers"). */
  path: string;
  /** Items in this folder and all of its subfolders. */
  count: number;
  children: FolderNode[];
}

const sameFolder = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** The folder tree of `items`, alphabetical at each level. */
export function buildFolderTree(items: readonly VaultItemData[]): FolderNode[] {
  const root: FolderNode[] = [];
  for (const item of items) {
    if (!item.folder) continue;
    let level = root;
    let path = '';
    for (const name of item.folder.split('/')) {
      let node = level.find((candidate) => sameFolder(candidate.name, name));
      if (!node) {
        node = { name, path: path ? `${path}/${name}` : name, count: 0, children: [] };
        level.push(node);
      }
      node.count++;
      path = node.path;
      level = node.children;
    }
  }
  const sort = (nodes: FolderNode[]): FolderNode[] =>
    nodes
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
      .map((node) => ({ ...node, children: sort(node.children) }));
  return sort(root);
}

/** Is the item in `path`, or (by default) in one of its subfolders? */
export function isInFolder(item: VaultItemData, path: string, includeSubfolders = true): boolean {
  if (!item.folder) return false;
  const folder = item.folder.toLowerCase();
  const target = path.toLowerCase();
  return folder === target || (includeSubfolders && folder.startsWith(`${target}/`));
}

/** "Work/Servers" → "Work"; a top-level folder has no parent. */
export const parentFolder = (path: string): string | undefined =>
  path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : undefined;

/** A copy of the item in `folder` (normalized), or in no folder when it's empty. */
export function withFolder(item: VaultItemData, folder: string | undefined): VaultItemData {
  const path = folder ? normalizeFolder(folder) : undefined;
  const copy: VaultItemData = { ...item };
  if (path) copy.folder = path;
  else delete copy.folder;
  return copy;
}

/**
 * The saves that move folder `from`, with its subfolders, to `to` (a rename),
 * or to no folder at all when `to` is undefined. Deleting a folder is moving
 * it to its {@link parentFolder}: its items are kept. Items already in the
 * right place are left out. Throws a RangeError if a path would be too deep.
 */
export function moveFolder(
  items: readonly VaultItem[],
  from: string,
  to: string | undefined,
): { item: VaultItem; data: VaultItemData }[] {
  return items
    .filter((item) => isInFolder(item, from))
    .map((item) => {
      const below = item.folder!.slice(from.length); // "" or "/Servers"
      return { item, data: withFolder(item, `${to ?? ''}${below}`) };
    })
    .filter(({ item, data }) => data.folder !== item.folder);
}

/** Every folder path in the tree, parents before their children (for suggestions). */
export const folderPaths = (tree: readonly FolderNode[]): string[] =>
  tree.flatMap((node) => [node.path, ...folderPaths(node.children)]);
