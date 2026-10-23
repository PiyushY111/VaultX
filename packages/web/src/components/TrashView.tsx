import { TRASH_RETENTION_DAYS, isLogin, type VaultItem } from '../vault/items';

interface Props {
  /** Items in the trash. */
  items: VaultItem[];
  now: Date;
  onRestore: (item: VaultItem) => void;
  onDeleteForever: (item: VaultItem) => void;
  onEmpty: () => void;
  onClose: () => void;
}

const DAY_MS = 24 * 60 * 60 * 1000;

function trashAge(deletedAt: string, now: Date): string {
  const days = Math.max(0, Math.floor((now.getTime() - Date.parse(deletedAt)) / DAY_MS));
  const left = Math.max(0, TRASH_RETENTION_DAYS - days);
  const ago = days === 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`;
  const purge = left <= 1 ? 'within a day' : `in ${left} days`;
  return `Moved here ${ago} · deleted for good ${purge}`;
}

/** The trash: restore items, or delete them now instead of after the retention period. */
export function TrashView({ items, now, onRestore, onDeleteForever, onEmpty, onClose }: Props) {
  const newestFirst = [...items].sort((a, b) => b.deletedAt!.localeCompare(a.deletedAt!));

  return (
    <section aria-label="Trash">
      <div className="vault-head">
        <h2>Trash</h2>
        <button type="button" className="btn btn-quiet" onClick={onClose}>
          Back to vault
        </button>
      </div>
      <p className="hint">
        Items stay here for {TRASH_RETENTION_DAYS} days, then are deleted for good the next time you
        open your vault. They’re still encrypted in your vault until then, and never filled in by
        the extension.
      </p>
      {newestFirst.length === 0 ? (
        <p className="quiet-state">The trash is empty.</p>
      ) : (
        <>
          <div className="row">
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                const count = newestFirst.length;
                const what = count === 1 ? 'this item' : `these ${count} items`;
                if (window.confirm(`Delete ${what} for good? This can’t be undone.`)) onEmpty();
              }}
            >
              Empty trash
            </button>
          </div>
          <ul className="ledger">
            {newestFirst.map((item) => (
              <li key={item.id} className="entry" aria-label={item.site}>
                <div className="entry-body">
                  <strong className="entry-site">{item.site}</strong>
                  {isLogin(item) && item.username && (
                    <span className="entry-user">{item.username}</span>
                  )}
                  <span className="entry-notes">{trashAge(item.deletedAt!, now)}</span>
                </div>
                <div className="entry-actions">
                  <button type="button" className="btn btn-quiet" onClick={() => onRestore(item)}>
                    Restore
                  </button>
                  <button
                    type="button"
                    className="btn btn-quiet btn-danger"
                    onClick={() => {
                      if (window.confirm(`Delete ${item.site} for good? This can’t be undone.`))
                        onDeleteForever(item);
                    }}
                  >
                    Delete forever
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
