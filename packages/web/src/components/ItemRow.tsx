import { useState } from 'react';
import { CLIPBOARD_CLEAR_MS, copySecret } from '../lib/clipboard';
import { groupDigits, useTotp } from '../lib/useTotp';
import { isLogin, type VaultItem } from '../vault/items';

interface Props {
  item: VaultItem;
  onEdit: () => void;
  onDelete: () => void;
  onToggleFavorite: () => void;
}

/** First letter of the item's name, shown in a small crest. */
function crestLetter(site: string): string {
  const name = site.replace(/^[a-z]+:\/\//i, '').replace(/^www\./i, '');
  return (name.match(/[\p{L}\p{N}]/u)?.[0] ?? '?').toUpperCase();
}

const TYPE_LABELS = { note: 'Secure note', card: 'Card', identity: 'Identity' } as const;

/** "4111 1111 1111 1111" → "•••• •••• •••• 1111" */
const maskCard = (number: string) => {
  const digits = number.replace(/\D/g, '');
  return digits.length > 4 ? `•••• •••• •••• ${digits.slice(-4)}` : '••••';
};

export function ItemRow({ item, onEdit, onDelete, onToggleFavorite }: Props) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const login = isLogin(item);
  const totp = useTotp(login ? item.totp : undefined);
  const fields = item.fields ?? {};

  async function copy(what: string, value: string) {
    try {
      await copySecret(value);
      setCopied(what);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      // Clipboard permission denied; the user can reveal and copy manually.
    }
  }

  const copyTitle = `Copies it; it’s cleared from the clipboard after ${CLIPBOARD_CLEAR_MS / 1000} seconds`;
  const identityName = [fields.firstName, fields.lastName].filter(Boolean).join(' ');
  const identityAddress = [fields.address, fields.city, fields.postalCode, fields.country]
    .filter(Boolean)
    .join(', ');

  return (
    <li className="entry" aria-label={item.site} data-type={item.type ?? 'login'}>
      <span className="initial" aria-hidden="true">
        {crestLetter(item.site)}
      </span>
      <div className="entry-body">
        <strong className="entry-site">
          {item.site}
          {item.type && item.type !== 'login' && (
            <span className="entry-type">{TYPE_LABELS[item.type]}</span>
          )}
        </strong>
        {login && item.username && <span className="entry-user">{item.username}</span>}
        {login && (
          <code className={revealed ? 'entry-secret is-revealed' : 'entry-secret'}>
            {revealed ? item.password : '••••••••••••'}
          </code>
        )}
        {totp.kind === 'code' && (
          <span className="entry-totp">
            <code aria-label="Two-factor code">{groupDigits(totp.code)}</code>
            <span
              className="totp-ring"
              role="timer"
              aria-label={`${totp.secondsLeft} seconds left`}
              style={{ ['--left' as string]: totp.secondsLeft / totp.period }}
            />
            <button type="button" className="btn btn-quiet" onClick={() => copy('code', totp.code)}>
              {copied === 'code' ? 'Copied' : 'Copy code'}
            </button>
          </span>
        )}
        {totp.kind === 'invalid' && (
          <span className="entry-notes">Two-factor setup key is invalid: {totp.message}</span>
        )}
        {item.type === 'card' && (
          <>
            {fields.cardholder && <span className="entry-user">{fields.cardholder}</span>}
            <code className={revealed ? 'entry-secret is-revealed' : 'entry-secret'}>
              {revealed ? fields.number || '(no number)' : maskCard(fields.number ?? '')}
            </code>
            <span className="entry-user">
              {fields.expiry && `Expires ${fields.expiry}`}
              {fields.cvv && ` · Security code ${revealed ? fields.cvv : '•••'}`}
            </span>
          </>
        )}
        {item.type === 'identity' && (
          <>
            {identityName && <span className="entry-user">{identityName}</span>}
            {(fields.email || fields.phone) && (
              <span className="entry-user">
                {[fields.email, fields.phone].filter(Boolean).join(' · ')}
              </span>
            )}
            {identityAddress && <span className="entry-user">{identityAddress}</span>}
          </>
        )}
        {item.notes && <p className="entry-notes">{item.notes}</p>}
        {item.tags && item.tags.length > 0 && (
          <ul className="entry-tags" aria-label="Tags">
            {item.tags.map((tag) => (
              <li key={tag}>{tag}</li>
            ))}
          </ul>
        )}
      </div>
      <div className="entry-actions">
        <button
          type="button"
          className={item.favorite ? 'btn btn-quiet star is-on' : 'btn btn-quiet star'}
          aria-pressed={Boolean(item.favorite)}
          aria-label="Favorite"
          title={item.favorite ? 'Remove from favorites' : 'Add to favorites'}
          onClick={onToggleFavorite}
        >
          {item.favorite ? '★' : '☆'}
        </button>
        {(login || item.type === 'card') && (
          <button type="button" className="btn btn-quiet" onClick={() => setRevealed((v) => !v)}>
            {revealed ? 'Hide' : 'Show'}
          </button>
        )}
        {login && (
          <button
            type="button"
            className="btn btn-quiet"
            onClick={() => copy('password', item.password)}
            title={copyTitle}
          >
            {copied === 'password' ? 'Copied' : 'Copy'}
          </button>
        )}
        {item.type === 'card' && fields.number && (
          <button
            type="button"
            className="btn btn-quiet"
            onClick={() => copy('number', fields.number!.replace(/\s/g, ''))}
            title={copyTitle}
          >
            {copied === 'number' ? 'Copied' : 'Copy number'}
          </button>
        )}
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
