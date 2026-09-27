import { useId, useState, type FormEvent } from 'react';
import { usePasswordStrength } from '../lib/passwordStrength';
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

  const set = (field: keyof VaultItemData) => (event: { target: { value: string } }) =>
    setData((prev) => ({ ...prev, [field]: event.target.value }));

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSave(data);
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
