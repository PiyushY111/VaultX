import { useEffect, useId, useState, type FormEvent } from 'react';
import { copySecret } from '../lib/clipboard';
import { usePasswordStrength } from '../lib/passwordStrength';
import { publicSuffixSite } from '../lib/publicSuffix';
import { groupDigits, readTotp, useTotp } from '../lib/useTotp';
import {
  CARD_FIELDS,
  IDENTITY_FIELDS,
  ITEM_TYPES,
  MATCH_MODES,
  emptyItem,
  isLogin,
  normalizeTags,
  type ItemType,
  type MatchMode,
  type VaultItemData,
} from '../vault/items';
import { withFolder } from '../vault/folders';
import { PasswordGenerator } from './PasswordGenerator';
import { StrengthMeter } from './StrengthMeter';

interface Props {
  initial: VaultItemData;
  isNew: boolean;
  onSave: (data: VaultItemData) => Promise<void>;
  onCancel: () => void;
  /** Folders already in the vault, suggested as you type. */
  folders?: readonly string[];
}

const TYPE_LABELS: Record<ItemType, string> = {
  login: 'Login',
  note: 'Secure note',
  card: 'Card',
  identity: 'Identity',
};

const MATCH_LABELS: Record<MatchMode, string> = {
  host: 'This site and its subdomains (default)',
  domain: 'Anywhere on the site’s domain',
  exact: 'This exact address only',
  never: 'Never fill it on a page',
};

const MATCH_HINTS: Record<MatchMode, string> = {
  host: 'Saved for login.example.com, it’s filled there and on a.login.example.com.',
  domain:
    'Saved for login.example.com, it’s also filled on example.com and shop.example.com. Use it only if you trust every part of the site.',
  exact: 'Saved for login.example.com, it’s filled there only, not on its subdomains.',
  never: 'The extension won’t offer it on any page; copy it from the popup instead.',
};

/** How long to wait after typing in the site before checking it against the suffix list. */
const SUFFIX_CHECK_DELAY_MS = 300;

const formatDate = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });

export function ItemForm({ initial, isNew, onSave, onCancel, folders = [] }: Props) {
  const passwordId = useId();
  const totpId = useId();
  const foldersId = useId();
  const [data, setData] = useState(initial);
  const [tagsText, setTagsText] = useState((initial.tags ?? []).join(', '));
  const [folderText, setFolderText] = useState(initial.folder ?? '');
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
  const [suffixSite, setSuffixSite] = useState<string | null>(null);
  const match: MatchMode = data.match ?? 'host';

  // A login saved for a public suffix (co.uk) would never be filled: say so while typing.
  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      if (!login) return setSuffixSite(null);
      publicSuffixSite(data.site).then(
        (host) => active && setSuffixSite(host),
        () => active && setSuffixSite(null),
      );
    }, SUFFIX_CHECK_DELAY_MS);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [login, data.site]);
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
    let saved: VaultItemData;
    try {
      const { totp: rawTotp, fields, ...rest } = data;
      const tags = normalizeTags(tagsText);
      saved = withFolder(
        {
          ...rest,
          ...(login && rawTotp?.trim() && { totp: rawTotp.trim() }),
          ...(tags.length && { tags }),
          ...(fields && { fields }),
        },
        folderText,
      );
    } catch (err) {
      // A folder path too deep or too long.
      setError(`Folder: ${(err as Error).message}`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSave(saved);
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
      {suffixSite && (
        <p className="warning" role="status">
          VaultX won’t fill this login anywhere: “{suffixSite}” is a shared suffix, not a website.
          Use the site’s full address, like login.example.{suffixSite}.
        </p>
      )}

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
      <label>
        Folder
        <input
          autoComplete="off"
          placeholder="Work/Servers (use / for a folder inside another)"
          list={foldersId}
          value={folderText}
          onChange={(e) => setFolderText(e.target.value)}
        />
        <datalist id={foldersId}>
          {folders.map((path) => (
            <option key={path} value={path} />
          ))}
        </datalist>
      </label>
      <label className="inline">
        <input
          type="checkbox"
          checked={Boolean(data.favorite)}
          onChange={(e) => setData((prev) => ({ ...prev, favorite: e.target.checked }))}
        />
        Favorite (shown first in the vault)
      </label>
      {login && (
        <details className="advanced">
          <summary>Advanced</summary>
          <label>
            Fill on
            <select
              value={match}
              onChange={(e) => setData((prev) => ({ ...prev, match: e.target.value as MatchMode }))}
            >
              {MATCH_MODES.map((mode) => (
                <option key={mode} value={mode}>
                  {MATCH_LABELS[mode]}
                </option>
              ))}
            </select>
          </label>
          <p className="hint">{MATCH_HINTS[match]}</p>
        </details>
      )}

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
