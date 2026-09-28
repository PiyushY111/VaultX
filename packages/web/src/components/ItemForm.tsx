import { useId, useState, type FormEvent } from 'react';
import { usePasswordStrength } from '../lib/passwordStrength';
import { groupDigits, readTotp, useTotp } from '../lib/useTotp';
import type { VaultItemData } from '../vault/items';
import { PasswordGenerator } from './PasswordGenerator';
import { StrengthMeter } from './StrengthMeter';

interface Props {
  initial: VaultItemData;
  isNew: boolean;
  onSave: (data: VaultItemData) => Promise<void>;
  onCancel: () => void;
}

export function ItemForm({ initial, isNew, onSave, onCancel }: Props) {
  const passwordId = useId();
  const [data, setData] = useState(initial);
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Advice only: a site may force a weak password on you.
  const strength = usePasswordStrength(data.password, [data.site, data.username]);

  const totp = useTotp(data.totp);
  const totpId = useId();

  const set = (field: keyof VaultItemData) => (event: { target: { value: string } }) =>
    setData((prev) => ({ ...prev, [field]: event.target.value }));

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const parsedTotp = readTotp(data.totp ?? '');
    if (typeof parsedTotp === 'string') {
      setError(`Two-factor setup key: ${parsedTotp}`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const { totp: rawTotp, ...rest } = data;
      await onSave(parsedTotp && rawTotp ? { ...rest, totp: rawTotp.trim() } : rest);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed');
      setBusy(false);
    }
  }

  return (
    <form className="sheet" onSubmit={handleSubmit} aria-label={isNew ? 'Add item' : 'Edit item'}>
      <h2>{isNew ? 'Add item' : 'Edit item'}</h2>
      <label>
        Site
        <input required autoComplete="off" value={data.site} onChange={set('site')} />
      </label>
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
      <label>
        Notes
        <textarea rows={4} value={data.notes} onChange={set('notes')} />
      </label>
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
