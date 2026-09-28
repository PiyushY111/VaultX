import { useEffect, useState, type FormEvent } from 'react';
import { SecondFactorRequiredError, logIn, type VaultSession } from '../vault/session';

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
  /** Set once the password checked out and the account wants a two-factor code. */
  const [pending, setPending] = useState<SecondFactorRequiredError | null>(null);

  // Don't leave derived keys waiting if the form goes away mid-login.
  useEffect(() => () => pending?.cancel(), [pending]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const submittedPassword = password;
    setPassword(''); // Don't keep the master password in state longer than needed.
    setBusy(true);
    setError(null);
    try {
      onUnlocked(await logIn(lockedEmail ?? email, submittedPassword));
    } catch (err) {
      if (err instanceof SecondFactorRequiredError) setPending(err);
      else setError(err instanceof Error ? err.message : 'Login failed');
      setBusy(false);
    }
  }

  if (pending) {
    return (
      <SecondFactorForm
        pending={pending}
        onUnlocked={onUnlocked}
        onCancel={() => {
          pending.cancel();
          setPending(null);
        }}
      />
    );
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

function SecondFactorForm({
  pending,
  onUnlocked,
  onCancel,
}: {
  pending: SecondFactorRequiredError;
  onUnlocked: (session: VaultSession) => void;
  onCancel: () => void;
}) {
  const [useRecovery, setUseRecovery] = useState(false);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onUnlocked(
        await pending.complete(
          useRecovery ? { recovery_code: code.trim() } : { totp_code: code.trim() },
        ),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setCode('');
      setBusy(false);
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit} aria-label="Two-factor code">
      <h2>Two-factor code</h2>
      <p className="lede">
        {useRecovery
          ? 'Enter one of your recovery codes. Each one works once.'
          : 'Enter the 6-digit code from your authenticator app.'}
      </p>
      <label>
        {useRecovery ? 'Recovery code' : 'Authentication code'}
        <input
          key={useRecovery ? 'recovery' : 'totp'}
          autoComplete="one-time-code"
          inputMode={useRecovery ? 'text' : 'numeric'}
          pattern={useRecovery ? undefined : '[0-9]{6}'}
          required
          autoFocus
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? 'Checking…' : 'Verify'}
      </button>
      <p className="links">
        <button
          type="button"
          className="link"
          onClick={() => {
            setUseRecovery((v) => !v);
            setCode('');
            setError(null);
          }}
        >
          {useRecovery ? 'Use my authenticator app' : 'Use a recovery code'}
        </button>
        <button type="button" className="link" onClick={onCancel}>
          Cancel
        </button>
      </p>
    </form>
  );
}
