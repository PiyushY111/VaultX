import { useState } from 'react';
import { CLIPBOARD_CLEAR_MS, copySecret } from '../lib/clipboard';
import { groupDigits, useTotp } from '../lib/useTotp';
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
  const [copiedCode, setCopiedCode] = useState(false);
  const totp = useTotp(item.totp);

  async function copyCode() {
    if (totp.kind !== 'code') return;
    try {
      await copySecret(totp.code);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    } catch {
      // Clipboard permission denied.
    }
  }

  async function copyPassword() {
    try {
      await copySecret(item.password);
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
        {totp.kind === 'code' && (
          <span className="entry-totp">
            <code aria-label="Two-factor code">{groupDigits(totp.code)}</code>
            <span
              className="totp-ring"
              role="timer"
              aria-label={`${totp.secondsLeft} seconds left`}
              style={{ ['--left' as string]: totp.secondsLeft / totp.period }}
            />
            <button type="button" className="btn btn-quiet" onClick={copyCode}>
              {copiedCode ? 'Copied' : 'Copy code'}
            </button>
          </span>
        )}
        {totp.kind === 'invalid' && (
          <span className="entry-notes">Two-factor setup key is invalid: {totp.message}</span>
        )}
        {item.notes && <p className="entry-notes">{item.notes}</p>}
      </div>
      <div className="entry-actions">
        <button type="button" className="btn btn-quiet" onClick={() => setRevealed((v) => !v)}>
          {revealed ? 'Hide' : 'Show'}
        </button>
        <button
          type="button"
          className="btn btn-quiet"
          onClick={copyPassword}
          title={`Copies the password; it’s cleared from the clipboard after ${CLIPBOARD_CLEAR_MS / 1000} seconds`}
        >
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
