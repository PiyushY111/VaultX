import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, api, type SessionInfo } from '../api';
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
  type VaultSession,
} from '../vault/session';
import { StrengthMeter } from './StrengthMeter';

interface Props {
  session: VaultSession;
  /** Every item in the vault, decrypted. Null while loading. */
  items: VaultItem[] | null;
  /** Why the vault can't be re-encrypted right now (some items didn't decrypt), if so. */
  changeBlockedReason: string | null;
  onPasswordChanged: (items: VaultItem[]) => void;
  onSignedOutEverywhere: () => void;
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
      <SessionList {...props} />
    </section>
  );
}

function ChangePasswordForm({
  session,
  items,
  changeBlockedReason,
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
      onPasswordChanged(await changeMasterPassword(session, currentPassword, newPassword, items));
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
