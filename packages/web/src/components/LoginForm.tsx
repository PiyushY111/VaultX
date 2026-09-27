import { useState, type FormEvent } from 'react';
import { logIn, type VaultSession } from '../vault/session';

interface Props {
  /** When set, this is the unlock screen for an auto-locked or manually locked vault. */
  lockedEmail?: string;
  onUnlocked: (session: VaultSession) => void;
  onSwitchToSignup: () => void;
  onSwitchAccount?: () => void;
}

export function LoginForm({ lockedEmail, onUnlocked, onSwitchToSignup, onSwitchAccount }: Props) {
  const [email, setEmail] = useState(lockedEmail ?? '');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const submittedPassword = password;
    setPassword(''); // Don't keep the master password in state longer than needed.
    setBusy(true);
    setError(null);
    try {
      onUnlocked(await logIn(lockedEmail ?? email, submittedPassword));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setBusy(false);
    }
  }

  return (
    <form
      className="auth-form"
      onSubmit={handleSubmit}
      aria-label={lockedEmail ? 'Unlock vault' : 'Log in'}
    >
      <h2>{lockedEmail ? 'Vault locked' : 'Log in'}</h2>
      {lockedEmail ? (
        <p className="lede">
          Enter the master password for <strong>{lockedEmail}</strong> to open it again.
        </p>
      ) : (
        <>
          <p className="lede">Your master password never leaves this device.</p>
          <label>
            Email
            <input
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>
        </>
      )}
      <label>
        Master password
        <input
          type="password"
          autoComplete="current-password"
          required
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? 'Deriving keys…' : lockedEmail ? 'Unlock' : 'Log in'}
      </button>
      <p className="links">
        {lockedEmail && onSwitchAccount ? (
          <button type="button" className="link" onClick={onSwitchAccount}>
            Use a different account
          </button>
        ) : (
          <button type="button" className="link" onClick={onSwitchToSignup}>
            Create an account
          </button>
        )}
      </p>
    </form>
  );
}
