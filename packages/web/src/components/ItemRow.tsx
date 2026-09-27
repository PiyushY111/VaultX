import { useState } from 'react';
import type { VaultItem } from '../vault/items';

interface Props {
  item: VaultItem;
  onEdit: () => void;
  onDelete: () => void;
}

/** First letter of the site's name, shown in a small crest. */
function crestLetter(site: string): string {
  const name = site.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '');
  return (name.match(/[\p{L}\p{N}]/u)?.[0] ?? '?').toUpperCase();
}

export function ItemRow({ item, onEdit, onDelete }: Props) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyPassword() {
    try {
      await navigator.clipboard.writeText(item.password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard permission denied; the user can reveal and copy manually.
    }
  }

  return (
    <li className="entry" aria-label={item.site}>
      <span className="initial" aria-hidden="true">
        {crestLetter(item.site)}
      </span>
      <div className="entry-body">
        <strong className="entry-site">{item.site}</strong>
        {item.username && <span className="entry-user">{item.username}</span>}
        <code className={revealed ? 'entry-secret is-revealed' : 'entry-secret'}>
          {revealed ? item.password : '••••••••••••'}
        </code>
        {item.notes && <p className="entry-notes">{item.notes}</p>}
      </div>
      <div className="entry-actions">
        <button type="button" className="btn btn-quiet" onClick={() => setRevealed((v) => !v)}>
          {revealed ? 'Hide' : 'Show'}
        </button>
        <button type="button" className="btn btn-quiet" onClick={copyPassword}>
          {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" className="btn btn-quiet" onClick={onEdit}>
          Edit
        </button>
        <button type="button" className="btn btn-quiet btn-danger" onClick={onDelete}>
          Delete
        </button>
      </div>
    </li>
  );
}
