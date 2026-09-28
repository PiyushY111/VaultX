import { useId, useState, type FormEvent } from 'react';
import { copySecret } from '../lib/clipboard';
import { usePasswordStrength } from '../lib/passwordStrength';
import { groupDigits, readTotp, useTotp } from '../lib/useTotp';
import {
  CARD_FIELDS,
  IDENTITY_FIELDS,
  ITEM_TYPES,
  emptyItem,
  isLogin,
  normalizeTags,
  type ItemType,
  type VaultItemData,
} from '../vault/items';
import { PasswordGenerator } from './PasswordGenerator';
import { StrengthMeter } from './StrengthMeter';

interface Props {
  initial: VaultItemData;
  isNew: boolean;
  onSave: (data: VaultItemData) => Promise<void>;
  onCancel: () => void;
}

const TYPE_LABELS: Record<ItemType, string> = {
  login: 'Login',
  note: 'Secure note',
  card: 'Card',
  identity: 'Identity',
};

const formatDate = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

export function ItemForm({ initial, isNew, onSave, onCancel }: Props) {
  const passwordId = useId();
  const totpId = useId();
  const [data, setData] = useState(initial);
  const [tagsText, setTagsText] = useState((initial.tags ?? []).join(', '));
  const [showPassword, setShowPassword] = useState(false);
  const [showSecrets, setShowSecrets] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const type: ItemType = data.type ?? 'login';
  const login = isLogin(data);
  // Advice only: a site may force a weak password on you.
  const strength = usePasswordStrength(login ? data.password : '', [data.site, data.username]);
  const totp = useTotp(login ? data.totp : undefined);

  const set =
    (field: 'site' | 'username' | 'password' | 'notes' | 'totp') =>
    (event: { target: { value: string } }) =>
      setData((prev) => ({ ...prev, [field]: event.target.value }));
  const setField = (key: string) => (event: { target: { value: string } }) =>
    setData((prev) => ({ ...prev, fields: { ...prev.fields, [key]: event.target.value } }));

  function changeType(next: ItemType) {
    // A new item can change kind until it's saved; the title and notes carry over.
    setData((prev) => ({ ...emptyItem(next), site: prev.site, notes: prev.notes }));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (login) {
      const parsedTotp = readTotp(data.totp ?? '');
      if (typeof parsedTotp === 'string') {
        setError(`Two-factor setup key: ${parsedTotp}`);
        return;
      }
    }
    setBusy(true);
    setError(null);
    try {
      const { totp: rawTotp, fields, ...rest } = data;
      const tags = normalizeTags(tagsText);
      await onSave({
        ...rest,
        ...(login && rawTotp?.trim() && { totp: rawTotp.trim() }),
        ...(tags.length && { tags }),
        ...(fields && { fields }),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
      setBusy(false);
    }
  }

  const history = data.history ?? [];

  return (
    <form className="sheet" onSubmit={handleSubmit} aria-label={isNew ? 'Add item' : 'Edit item'}>
      <h2>{isNew ? 'Add item' : `Edit ${TYPE_LABELS[type].toLowerCase()}`}</h2>
      {isNew && (
        <label>
          Type
          <select value={type} onChange={(e) => changeType(e.target.value as ItemType)}>
            {ITEM_TYPES.map((kind) => (
              <option key={kind} value={kind}>
                {TYPE_LABELS[kind]}
              </option>
            ))}
          </select>
        </label>
      )}
      <label>
        {login ? 'Site' : 'Title'}
        <input required autoComplete="off" value={data.site} onChange={set('site')} />
      </label>

      {login && (
        <>
          <label>
            Username
            <input autoComplete="off" value={data.username} onChange={set('username')} />
          </label>
          <div className="field">
            <label htmlFor={passwordId}>Password</label>
            <div className="row">
              <input
                id={passwordId}
                className="secret-input"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                value={data.password}
                onChange={set('password')}
              />
              <button type="button" className="btn" onClick={() => setShowPassword((v) => !v)}>
                {showPassword ? 'Hide' : 'Show'}
              </button>
              <button
                type="button"
                className="btn"
                aria-expanded={showGenerator}
                onClick={() => setShowGenerator((v) => !v)}
              >
                Generate…
              </button>
            </div>
            <StrengthMeter strength={strength} />
          </div>
          {showGenerator && (
            <PasswordGenerator
              onUse={(password) => {
                setData((prev) => ({ ...prev, password }));
                setShowGenerator(false);
              }}
            />
          )}
          <div className="field">
            <label htmlFor={totpId}>Two-factor setup key (optional)</label>
            <input
              id={totpId}
              className="secret-input"
              autoComplete="off"
              spellCheck={false}
              placeholder="Setup key or otpauth:// link"
              value={data.totp ?? ''}
              onChange={set('totp')}
              aria-describedby={`${totpId}-hint`}
            />
            <p className="hint" id={`${totpId}-hint`}>
              {totp.kind === 'code'
                ? `Current code: ${groupDigits(totp.code)}${totp.config.issuer ? ` (${totp.config.issuer})` : ''}. Check it matches the site before saving.`
                : totp.kind === 'invalid'
                  ? totp.message
                  : 'When a site shows a QR code to set up two-factor login, choose “enter the key manually” and paste the key here. VaultX will then show the site’s codes.'}
            </p>
          </div>
        </>
      )}

      {type === 'card' && (
        <>
          {CARD_FIELDS.map(([key, label, secret]) => (
            <label key={key}>
              {label}
              <input
                className={secret ? 'secret-input' : undefined}
                type={secret && !showSecrets ? 'password' : 'text'}
                autoComplete="off"
                inputMode={key === 'number' || key === 'cvv' ? 'numeric' : undefined}
                value={data.fields?.[key] ?? ''}
                onChange={setField(key)}
              />
            </label>
          ))}
          <div className="row">
            <button type="button" className="btn" onClick={() => setShowSecrets((v) => !v)}>
              {showSecrets ? 'Hide card details' : 'Show card details'}
            </button>
          </div>
        </>
      )}

      {type === 'identity' &&
        IDENTITY_FIELDS.map(([key, label]) => (
          <label key={key}>
            {label}
            <input
              autoComplete="off"
              type={key === 'email' ? 'email' : key === 'phone' ? 'tel' : 'text'}
              value={data.fields?.[key] ?? ''}
              onChange={setField(key)}
            />
          </label>
        ))}

      <label>
        Notes
        <textarea rows={type === 'note' ? 8 : 4} value={data.notes} onChange={set('notes')} />
      </label>
      <label>
        Tags
        <input
          autoComplete="off"
          placeholder="work, banking, shared…"
          value={tagsText}
          onChange={(e) => setTagsText(e.target.value)}
        />
      </label>
      <label className="inline">
        <input
          type="checkbox"
          checked={Boolean(data.favorite)}
          onChange={(e) => setData((prev) => ({ ...prev, favorite: e.target.checked }))}
        />
        Favorite (shown first in the vault)
      </label>

      {login && !isNew && history.length > 0 && (
        <div className="field history" role="region" aria-label="Password history">
          <div className="row">
            <button
              type="button"
              className="btn"
              aria-expanded={showHistory}
              onClick={() => setShowHistory((v) => !v)}
            >
              {showHistory ? 'Hide' : 'Show'} password history ({history.length})
            </button>
            <button
              type="button"
              className="btn btn-quiet btn-danger"
              onClick={() => setData((prev) => ({ ...prev, history: [] }))}
            >
              Clear history
            </button>
          </div>
          {showHistory && (
            <ul className="history-list">
              {[...history].reverse().map((entry, index) => (
                <li key={index}>
                  <code className="entry-secret is-revealed">{entry.password}</code>
                  <span className="hint">replaced {formatDate(entry.changedAt)}</span>
                  <button
                    type="button"
                    className="btn btn-quiet"
                    onClick={() => void copySecret(entry.password).catch(() => {})}
                  >
                    Copy
                  </button>
                </li>
              ))}
            </ul>
          )}
          <p className="hint">
            Earlier passwords stay encrypted in this item (the last 10) in case a change didn’t
            take. Clearing removes them on save.
          </p>
        </div>
      )}

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="row sheet-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? 'Encrypting…' : 'Save'}
        </button>
        <button type="button" className="btn btn-quiet" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  );
}
