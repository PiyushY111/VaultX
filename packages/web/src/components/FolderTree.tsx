import { useState, type FormEvent } from 'react';
import { parentFolder, type FolderNode } from '../vault/folders';

interface Props {
  tree: FolderNode[];
  /** Items in the vault, and those in no folder. */
  total: number;
  looseCount: number;
  /** null for all items, '' for items in no folder, or a folder's path. */
  selected: string | null;
  onSelect: (folder: string | null) => void;
  /** Rejects with a message if the new name can't be used. */
  onRename: (from: string, to: string) => Promise<void>;
  onDelete: (path: string) => void;
}

function findNode(nodes: FolderNode[], path: string): FolderNode | undefined {
  for (const node of nodes) {
    if (node.path.toLowerCase() === path.toLowerCase()) return node;
    const found = findNode(node.children, path);
    if (found) return found;
  }
  return undefined;
}

/**
 * The vault's folders, to filter the list by. Which folders are collapsed is
 * kept in memory only: folder names can be sensitive, so they never go in
 * localStorage (or a URL).
 */
export function FolderTree({
  tree,
  total,
  looseCount,
  selected,
  onSelect,
  onRename,
  onDelete,
}: Props) {
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set());
  const [renaming, setRenaming] = useState(false);
  const [newName, setNewName] = useState('');
  const [renameError, setRenameError] = useState<string | null>(null);
  const current = selected ? findNode(tree, selected) : undefined;

  const toggle = (path: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });

  async function submitRename(event: FormEvent) {
    event.preventDefault();
    if (!current) return;
    try {
      await onRename(current.path, newName);
      setRenaming(false);
    } catch (err) {
      setRenameError(err instanceof Error ? err.message : 'Rename failed');
    }
  }

  function confirmDelete(node: FolderNode) {
    const parent = parentFolder(node.path);
    const items = node.count === 1 ? 'Its 1 item moves' : `Its ${node.count} items move`;
    const where = parent ? `to “${parent}”` : 'out of any folder';
    if (window.confirm(`Delete the folder “${node.path}”? ${items} ${where}; nothing is deleted.`))
      onDelete(node.path);
  }

  const entry = (label: string, count: number, folder: string | null) => (
    <button
      type="button"
      className="folder-button"
      aria-pressed={selected === folder}
      onClick={() => {
        setRenaming(false);
        onSelect(folder);
      }}
    >
      {label} <span className="folder-count">{count}</span>
    </button>
  );

  const branch = (nodes: FolderNode[]) => (
    <ul>
      {nodes.map((node) => {
        const open = !collapsed.has(node.path.toLowerCase());
        return (
          <li key={node.path}>
            {node.children.length > 0 ? (
              <button
                type="button"
                className="folder-toggle"
                aria-expanded={open}
                aria-label={`${open ? 'Collapse' : 'Expand'} ${node.name}`}
                onClick={() => toggle(node.path.toLowerCase())}
              >
                {open ? '▾' : '▸'}
              </button>
            ) : (
              <span className="folder-toggle" aria-hidden="true" />
            )}
            {entry(node.name, node.count, node.path)}
            {open && node.children.length > 0 && branch(node.children)}
          </li>
        );
      })}
    </ul>
  );

  return (
    <nav className="folders" aria-label="Folders">
      <ul>
        <li>{entry('All items', total, null)}</li>
      </ul>
      {branch(tree)}
      {looseCount > 0 && (
        <ul>
          <li>{entry('No folder', looseCount, '')}</li>
        </ul>
      )}
      {current &&
        (renaming ? (
          <form className="row" onSubmit={submitRename} aria-label="Rename folder">
            <input
              aria-label="New folder name"
              autoComplete="off"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <button type="submit" className="btn">
              Rename
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => setRenaming(false)}>
              Cancel
            </button>
            {renameError && (
              <p className="error" role="alert">
                {renameError}
              </p>
            )}
          </form>
        ) : (
          <div className="row">
            <button
              type="button"
              className="btn btn-quiet"
              onClick={() => {
                setNewName(current.path);
                setRenameError(null);
                setRenaming(true);
              }}
            >
              Rename folder
            </button>
            <button
              type="button"
              className="btn btn-quiet btn-danger"
              onClick={() => confirmDelete(current)}
            >
              Delete folder
            </button>
          </div>
        ))}
    </nav>
  );
}
