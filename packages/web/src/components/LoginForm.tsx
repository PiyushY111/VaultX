import { useEffect, useState, type FormEvent } from 'react';
import type { SecondFactor } from '../api';
import { getPasskeyAssertion } from '../lib/passkeys';
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

type FactorMode = 'passkey' | 'totp' | 'recovery';

function SecondFactorForm({
  pending,
  onUnlocked,
  onCancel,
}: {
  pending: SecondFactorRequiredError;
  onUnlocked: (session: VaultSession) => void;
  onCancel: () => void;
}) {
  const { methods } = pending.challenge;
  const hasPasskey = methods.includes('webauthn');
  const hasTotp = methods.includes('totp');
  const [mode, setMode] = useState<FactorMode>(
    hasPasskey ? 'passkey' : hasTotp ? 'totp' : 'recovery',
  );
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(factor: () => Promise<SecondFactor>) {
    setBusy(true);
    setError(null);
    try {
      onUnlocked(await pending.complete(await factor()));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setCode('');
      setBusy(false);
    }
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (mode === 'passkey') {
      return send(async () => {
        const options = pending.challenge.webauthnOptions;
        if (!options) throw new Error('The server didn’t send a passkey challenge. Try again.');
        return { webauthn: await getPasskeyAssertion(options) };
      });
    }
    const trimmed = code.trim();
    return send(async () =>
      mode === 'recovery' ? { recovery_code: trimmed } : { totp_code: trimmed },
    );
  }

  function switchTo(next: FactorMode) {
    setMode(next);
    setCode('');
    setError(null);
  }

  const others: [FactorMode, string][] = [];
  if (hasPasskey && mode !== 'passkey') others.push(['passkey', 'Use a passkey']);
  if (hasTotp && mode !== 'totp') others.push(['totp', 'Use my authenticator app']);
  if (mode !== 'recovery') others.push(['recovery', 'Use a recovery code']);

  return (
    <form className="auth-form" onSubmit={handleSubmit} aria-label="Two-factor code">
      <h2>{mode === 'passkey' ? 'Confirm with a passkey' : 'Two-factor code'}</h2>
      <p className="lede">
        {mode === 'passkey'
          ? 'Use the passkey you added for this account: your device will ask for your fingerprint, face, PIN or security key.'
          : mode === 'recovery'
            ? 'Enter one of your recovery codes. Each one works once.'
            : 'Enter the 6-digit code from your authenticator app.'}
      </p>
      {mode !== 'passkey' && (
        <label>
          {mode === 'recovery' ? 'Recovery code' : 'Authentication code'}
          <input
            key={mode}
            autoComplete="one-time-code"
            inputMode={mode === 'recovery' ? 'text' : 'numeric'}
            pattern={mode === 'recovery' ? undefined : '[0-9]{6}'}
            required
            autoFocus
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </label>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button
        type="submit"
        className="btn btn-primary"
        disabled={busy}
        autoFocus={mode === 'passkey'}
      >
        {busy ? 'Checking…' : mode === 'passkey' ? 'Use passkey' : 'Verify'}
      </button>
      <p className="links">
        {others.map(([next, label]) => (
          <button key={next} type="button" className="link" onClick={() => switchTo(next)}>
            {label}
          </button>
        ))}
        <button type="button" className="link" onClick={onCancel}>
          Cancel
        </button>
      </p>
    </form>
  );
}
