import type { VaultManifest } from '@password-manager/crypto';
import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, api, type AccountInfo, type Reauth, type SessionInfo } from '../api';
import { downloadText } from '../lib/download';
import {
  MIN_MASTER_PASSWORD_SCORE,
  WEAK_MASTER_PASSWORD,
  estimateStrength,
  usePasswordStrength,
} from '../lib/passwordStrength';
import { describeSession } from '../lib/sessionLabel';
import type { VaultItem } from '../vault/items';
import {
  MIN_MASTER_PASSWORD_LENGTH,
  changeMasterPassword,
  proveCurrentPassword,
  type VaultSession,
} from '../vault/session';
import { QrCode } from './QrCode';
import { StrengthMeter } from './StrengthMeter';

interface Props {
  session: VaultSession;
  /** Every item in the vault, decrypted. Null while loading. */
  items: VaultItem[] | null;
  /** Why the vault can't be re-encrypted right now (some items didn't decrypt), if so. */
  changeBlockedReason: string | null;
  /** The vault's current manifest (re-encrypted along with the items on a password change). */
  currentManifest: () => VaultManifest;
  onPasswordChanged: (items: VaultItem[], manifest: VaultManifest) => void;
  onShowEmergencyKit: () => void;
  onSignedOutEverywhere: () => void;
  onAccountDeleted: () => void;
  /** The server rejected this session. */
  onSessionExpired: () => void;
  onClose: () => void;
}

const formatTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function SecurityPanel(props: Props) {
  return (
    <section className="security" aria-label="Security">
      <div className="vault-head">
        <h2>Security</h2>
        <button type="button" className="btn btn-quiet" onClick={props.onClose}>
          Back to vault
        </button>
      </div>
      <ChangePasswordForm {...props} />
      <TwoFactorSection {...props} />
      <SessionList {...props} />
      <div className="sheet" role="region" aria-label="Emergency kit">
        <h3>Emergency kit</h3>
        <p className="hint">
          A sheet to print or download with your email and server address, and a space to write your
          master password by hand.
        </p>
        <div className="row sheet-actions">
          <button type="button" className="btn" onClick={props.onShowEmergencyKit}>
            Show emergency kit
          </button>
        </div>
      </div>
      <DeleteAccountSection {...props} />
    </section>
  );
}

function ChangePasswordForm({
  session,
  items,
  changeBlockedReason,
  currentManifest,
  onPasswordChanged,
  onSessionExpired,
}: Props) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const strength = usePasswordStrength(next, [session.email]);
  const tooWeak = strength !== null && strength.score < MIN_MASTER_PASSWORD_SCORE;
  const blocked = changeBlockedReason ?? (items === null ? 'Your vault is still loading.' : null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!items || blocked) return;
    setDone(false);
    if (next.length < MIN_MASTER_PASSWORD_LENGTH) {
      setError(`Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`);
      return;
    }
    if ((await estimateStrength(next, [session.email])).score < MIN_MASTER_PASSWORD_SCORE) {
      setError(WEAK_MASTER_PASSWORD);
      return;
    }
    if (next !== confirm) {
      setError('New passwords do not match.');
      return;
    }
    if (next === current) {
      setError('The new master password is the same as the current one.');
      return;
    }
    const [currentPassword, newPassword] = [current, next];
    setCurrent('');
    setNext('');
    setConfirm('');
    setBusy(true);
    setError(null);
    try {
      const changed = await changeMasterPassword(
        session,
        currentPassword,
        newPassword,
        items,
        currentManifest(),
      );
      onPasswordChanged(changed.items, changed.manifest);
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof Error ? err.message : 'Could not change the master password');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="sheet" onSubmit={handleSubmit} aria-label="Change master password">
      <h3>Change master password</h3>
      <p className="hint">
        This also replaces your vault key and re-encrypts every item on this device, then signs out
        your other sessions (they hold the old key). Use it if you think your master password has
        been exposed.
      </p>
      {blocked && (
        <p className="warning" role="status">
          {blocked}
        </p>
      )}
      <label>
        Current master password
        <input
          type="password"
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
      </label>
      <label>
        New master password
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={MIN_MASTER_PASSWORD_LENGTH}
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
      </label>
      <StrengthMeter strength={strength} requirement={tooWeak ? WEAK_MASTER_PASSWORD : undefined} />
      <label>
        Confirm new master password
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
      {done && (
        <p className="notice" role="status">
          Master password changed. Your vault was re-encrypted with a new key and your other
          sessions were signed out.
        </p>
      )}
      <div className="row sheet-actions">
        <button type="submit" className="btn btn-primary" disabled={busy || Boolean(blocked)}>
          {busy ? 'Re-encrypting vault…' : 'Change master password'}
        </button>
      </div>
    </form>
  );
}

function SessionList({ session, onSignedOutEverywhere, onSessionExpired }: Props) {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) onSessionExpired();
      else setError(err instanceof Error ? err.message : 'Something went wrong');
    },
    [onSessionExpired],
  );

  const load = useCallback(async () => {
    try {
      setSessions((await api.listSessions(session.token)).sessions);
    } catch (err) {
      handleError(err);
    }
  }, [session, handleError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function revoke(target: SessionInfo) {
    setError(null);
    try {
      await api.revokeSession(session.token, target.id);
      await load();
    } catch (err) {
      handleError(err);
    }
  }

  async function signOutEverywhere() {
    if (!window.confirm('Sign out of VaultX everywhere, including here?')) return;
    try {
      await api.revokeAllSessions(session.token);
      onSignedOutEverywhere();
    } catch (err) {
      handleError(err);
    }
  }

  return (
    <div className="sheet" aria-label="Sessions" role="region">
      <h3>Sessions</h3>
      <p className="hint">
        Everywhere you’re signed in. Sign out anything you don’t recognize, then change your master
        password.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {sessions === null ? (
        <p className="quiet-state">Loading sessions…</p>
      ) : (
        <ul className="sessions">
          {sessions.map((item) => (
            <li key={item.id} className="session" aria-label={describeSession(item)}>
              <div>
                <strong>{describeSession(item)}</strong>
                {item.current && <span className="badge">This session</span>}
                <p className="hint">
                  Signed in {formatTime(item.created_at)} · last used{' '}
                  {formatTime(item.last_used_at)}
                </p>
              </div>
              {!item.current && (
                <button type="button" className="btn btn-quiet" onClick={() => revoke(item)}>
                  Sign out
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <div className="row sheet-actions">
        <button type="button" className="btn btn-danger" onClick={signOutEverywhere}>
          Sign out everywhere
        </button>
      </div>
    </div>
  );
}

/** A 6-digit code from the app, or anything else as a recovery code. */
function secondFactorOf(code: string): Partial<Reauth> {
  const trimmed = code.trim();
  if (!trimmed) return {};
  return /^\d{6}$/.test(trimmed) ? { totp_code: trimmed } : { recovery_code: trimmed };
}

function useAccount(session: VaultSession, onSessionExpired: () => void) {
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const reload = useCallback(async () => {
    try {
      setAccount(await api.getAccount(session.token));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onSessionExpired();
    }
  }, [session, onSessionExpired]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return [account, reload] as const;
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = [
    'VaultX two-factor recovery codes',
    '',
    'Each code works once, instead of a code from your authenticator app.',
    '',
    ...codes,
    '',
  ].join('\n');
  return (
    <div className="recovery" role="region" aria-label="Recovery codes">
      <p className="warning">
        Save these recovery codes somewhere safe. Each one lets you log in once without your
        authenticator app. They won’t be shown again.
      </p>
      <ul className="recovery-codes">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="row sheet-actions">
        <button
          type="button"
          className="btn"
          onClick={() => downloadText('VaultX recovery codes.txt', text)}
        >
          Download
        </button>
        <button type="button" className="btn" onClick={() => window.print()}>
          Print
        </button>
        <button type="button" className="btn btn-primary" onClick={onDone}>
          I’ve saved them
        </button>
      </div>
    </div>
  );
}

type TwoFactorStep =
  | { kind: 'idle' }
  | { kind: 'setup'; secret: string; uri: string }
  | { kind: 'codes'; codes: string[] }
  | { kind: 'reauth'; action: 'disable' | 'regenerate' };

function TwoFactorSection({ session, onSessionExpired }: Props) {
  const [account, reload] = useAccount(session, onSessionExpired);
  const [step, setStep] = useState<TwoFactorStep>({ kind: 'idle' });
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function reset(next: TwoFactorStep = { kind: 'idle' }) {
    setStep(next);
    setPassword('');
    setCode('');
    setError(null);
  }

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setBusy(false);
    }
  }

  const startSetup = () =>
    run(async () => {
      const { secret, otpauth_uri } = await api.setupTotp(session.token);
      reset({ kind: 'setup', secret, uri: otpauth_uri });
    });

  const confirmSetup = (event: FormEvent) => {
    event.preventDefault();
    const [submitted, totp] = [password, code.trim()];
    setPassword('');
    return run(async () => {
      const authHash = await proveCurrentPassword(session, submitted);
      const { recovery_codes } = await api.enableTotp(session.token, {
        current_auth_hash: authHash,
        totp_code: totp,
      });
      reset({ kind: 'codes', codes: recovery_codes });
      await reload();
    });
  };

  const confirmReauth = (action: 'disable' | 'regenerate') => (event: FormEvent) => {
    event.preventDefault();
    const [submitted, factor] = [password, secondFactorOf(code)];
    setPassword('');
    return run(async () => {
      const body = { current_auth_hash: await proveCurrentPassword(session, submitted), ...factor };
      if (action === 'disable') {
        await api.disableTotp(session.token, body);
        reset();
      } else {
        const { recovery_codes } = await api.regenerateRecoveryCodes(session.token, body);
        reset({ kind: 'codes', codes: recovery_codes });
      }
      await reload();
    });
  };

  const passwordField = (
    <label>
      Master password
      <input
        type="password"
        autoComplete="current-password"
        required
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
    </label>
  );
  const errorLine = error && (
    <p className="error" role="alert">
      {error}
    </p>
  );

  return (
    <div className="sheet" role="region" aria-label="Two-factor login">
      <h3>Two-factor login</h3>
      <p className="hint">
        Asks for a 6-digit code from an authenticator app (such as Google Authenticator, 1Password
        or Aegis) each time you log in, so a stolen master password isn’t enough on its own.
      </p>
      {account === null ? (
        <p className="quiet-state">Loading…</p>
      ) : step.kind === 'codes' ? (
        <RecoveryCodes codes={step.codes} onDone={() => reset()} />
      ) : step.kind === 'setup' ? (
        <form className="totp-setup" onSubmit={confirmSetup} aria-label="Set up two-factor login">
          <p>1. Scan this code with your authenticator app, or enter the key by hand.</p>
          <QrCode text={step.uri} label="QR code for your authenticator app" />
          <p className="hint">
            Key: <span className="totp-secret">{step.secret.replace(/(.{4})/g, '$1 ').trim()}</span>
          </p>
          <p>2. Enter the 6-digit code it shows, and your master password.</p>
          <label>
            Code from the app
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              required
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </label>
          {passwordField}
          {errorLine}
          <div className="row sheet-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Checking…' : 'Turn on two-factor login'}
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => reset()}>
              Cancel
            </button>
          </div>
        </form>
      ) : step.kind === 'reauth' ? (
        <form
          onSubmit={confirmReauth(step.action)}
          aria-label={
            step.action === 'disable' ? 'Turn off two-factor login' : 'New recovery codes'
          }
        >
          {passwordField}
          <label>
            Code from your app, or a recovery code
            <input
              autoComplete="one-time-code"
              required
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </label>
          {errorLine}
          <div className="row sheet-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy
                ? 'Checking…'
                : step.action === 'disable'
                  ? 'Turn off two-factor login'
                  : 'Get new recovery codes'}
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => reset()}>
              Cancel
            </button>
          </div>
        </form>
      ) : account.totp_enabled ? (
        <>
          <p className="notice" role="status">
            Two-factor login is on. {account.recovery_codes_remaining} recovery code
            {account.recovery_codes_remaining === 1 ? '' : 's'} left.
          </p>
          {errorLine}
          <div className="row sheet-actions">
            <button
              type="button"
              className="btn"
              onClick={() => reset({ kind: 'reauth', action: 'regenerate' })}
            >
              New recovery codes
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => reset({ kind: 'reauth', action: 'disable' })}
            >
              Turn off
            </button>
          </div>
        </>
      ) : (
        <>
          {errorLine}
          <div className="row sheet-actions">
            <button type="button" className="btn btn-primary" onClick={startSetup} disabled={busy}>
              Set up two-factor login
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function DeleteAccountSection({ session, onAccountDeleted, onSessionExpired }: Props) {
  const [account] = useAccount(session, onSessionExpired);
  const [confirmEmail, setConfirmEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (confirmEmail.trim().toLowerCase() !== session.email) {
      setError('Type your email exactly to confirm.');
      return;
    }
    const submitted = password;
    setPassword('');
    setBusy(true);
    setError(null);
    try {
      const authHash = await proveCurrentPassword(session, submitted);
      await api.deleteAccount(session.token, {
        current_auth_hash: authHash,
        ...secondFactorOf(code),
      });
      onAccountDeleted();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof Error ? err.message : 'Could not delete the account');
      setBusy(false);
    }
  }

  return (
    <form className="sheet danger-zone" onSubmit={handleSubmit} aria-label="Delete account">
      <h3>Delete account</h3>
      <p className="warning">
        Permanently deletes your account and every item in your vault from the server. This can’t be
        undone. Download anything you need first.
      </p>
      <label>
        Type your email to confirm
        <input
          type="email"
          autoComplete="off"
          required
          value={confirmEmail}
          onChange={(e) => setConfirmEmail(e.target.value)}
        />
      </label>
      <label>
        Master password
        <input
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      {account?.totp_enabled && (
        <label>
          Code from your app, or a recovery code
          <input
            autoComplete="one-time-code"
            required
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
      <div className="row sheet-actions">
        <button type="submit" className="btn btn-danger" disabled={busy}>
          {busy ? 'Deleting…' : 'Delete account permanently'}
        </button>
      </div>
    </form>
  );
}
