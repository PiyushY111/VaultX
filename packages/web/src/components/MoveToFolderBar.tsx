import { useId, useState, type FormEvent } from 'react';

interface Props {
  /** How many items are selected. */
  count: number;
  /** Folders already in the vault, suggested as you type. */
  folders: readonly string[];
  /** '' moves the items out of any folder. Rejects with a message on failure. */
  onMove: (folder: string) => Promise<void>;
  onCancel: () => void;
}

/** Shown while items are being selected: moves them all to one folder in one save. */
export function MoveToFolderBar({ count, folders, onMove, onCancel }: Props) {
  const listId = useId();
  const [folder, setFolder] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onMove(folder);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Move failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="notice row" onSubmit={handleSubmit} aria-label="Move to folder">
      <span>{count} selected</span>
      <input
        aria-label="Folder to move them to"
        autoComplete="off"
        placeholder="Folder (empty for no folder)"
        list={listId}
        value={folder}
        onChange={(e) => setFolder(e.target.value)}
      />
      <datalist id={listId}>
        {folders.map((path) => (
          <option key={path} value={path} />
        ))}
      </datalist>
      <button type="submit" className="btn" disabled={busy || count === 0}>
        {busy ? 'Moving…' : 'Move'}
      </button>
      <button type="button" className="btn btn-quiet" onClick={onCancel}>
        Cancel
      </button>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}
