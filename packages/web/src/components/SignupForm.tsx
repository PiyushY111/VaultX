import { useState, type FormEvent } from 'react';
import { MIN_MASTER_PASSWORD_LENGTH, signUp, type VaultSession } from '../vault/session';

interface Props {
  onSignedUp: (session: VaultSession) => void;
  onSwitchToLogin: () => void;
}

export function SignupForm({ onSignedUp, onSwitchToLogin }: Props) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
      setError(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`);
      return;
    }
    // With zero-knowledge encryption a typo here means permanent lockout.
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    const submittedPassword = password;
    setPassword('');
    setConfirm('');
    setBusy(true);
    setError(null);
    try {
      onSignedUp(await signUp(email, submittedPassword));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-up failed');
      setBusy(false);
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit} aria-label="Create account">
      <h2>Create account</h2>
      <p className="warning">
        Your master password never leaves this device and cannot be recovered. If you forget it,
        your vault is lost.
      </p>
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
      <label>
        Master password
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_MASTER_PASSWORD_LENGTH}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      <label>
        Confirm master password
        <input
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? 'Deriving keys…' : 'Create account'}
      </button>
      <p className="links">
        <button type="button" className="link" onClick={onSwitchToLogin}>
          I already have an account
        </button>
      </p>
    </form>
  );
}
