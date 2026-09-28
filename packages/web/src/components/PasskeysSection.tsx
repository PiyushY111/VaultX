import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ApiError, api, type PasskeyInfo } from '../api';
import { createPasskey, passkeysSupported } from '../lib/passkeys';
import { proveCurrentPassword } from '../vault/session';
import type { SectionProps } from './SecurityPanel';
import {
  RecoveryCodes,
  SecondFactorField,
  defaultFactorMode,
  hasSecondFactor,
  resolveSecondFactor,
  type FactorMode,
} from './securityShared';

type Step =
  | { kind: 'idle' }
  | { kind: 'add' }
  | { kind: 'codes'; codes: string[] }
  | { kind: 'rename'; passkey: PasskeyInfo }
  | { kind: 'remove'; passkey: PasskeyInfo }
  | { kind: 'require'; required: boolean };

const formatDate = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

/** A default name from the browser, e.g. "Chrome on macOS"; the user can change it. */
function suggestedName(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /Firefox\//.test(ua)
      ? 'Firefox'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : 'Browser';
  const os = /Mac OS X/.test(ua)
    ? 'macOS'
    : /Windows/.test(ua)
      ? 'Windows'
      : /Android/.test(ua)
        ? 'Android'
        : /iPhone|iPad/.test(ua)
          ? 'iOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : '';
  return os ? `${browser} on ${os}` : browser;
}

/**
 * Passkeys as a second factor: phishing-resistant, because the browser only
 * lets a passkey sign for the site it was made on. Adding and removing one,
 * and "Require passkey", take the master password and an existing second
 * factor; renaming only changes a label.
 */
export function PasskeysSection({
  session,
  onSessionExpired,
  account,
  reloadAccount,
}: SectionProps) {
  const [passkeys, setPasskeys] = useState<PasskeyInfo[] | null>(null);
  const [step, setStep] = useState<Step>({ kind: 'idle' });
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [mode, setMode] = useState<FactorMode>('code');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setPasskeys((await api.listPasskeys(session.token)).passkeys);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onSessionExpired();
    }
  }, [session, onSessionExpired]);
  useEffect(() => {
    void load();
  }, [load]);

  function reset(next: Step = { kind: 'idle' }) {
    setStep(next);
    setName(
      next.kind === 'add' ? suggestedName() : next.kind === 'rename' ? next.passkey.name : '',
    );
    setPassword('');
    setCode('');
    setMode(defaultFactorMode(account));
    setError(null);
  }

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await Promise.all([load(), reloadAccount()]);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onSessionExpired();
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setBusy(false);
    }
  }

  /** The master password, checked locally first, plus a second factor if the account has one. */
  async function reauth(submitted: string) {
    const current_auth_hash = await proveCurrentPassword(session, submitted);
    return {
      current_auth_hash,
      ...(hasSecondFactor(account) ? await resolveSecondFactor(session, mode, code) : {}),
    };
  }

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const submitted = password;
    setPassword('');
    return run(async () => {
      if (step.kind === 'add') {
        const label = name.trim();
        const { options } = await api.passkeyRegistrationOptions(
          session.token,
          await reauth(submitted),
        );
        const { recovery_codes } = await api.registerPasskey(
          session.token,
          label,
          await createPasskey(options),
        );
        reset(recovery_codes ? { kind: 'codes', codes: recovery_codes } : { kind: 'idle' });
      } else if (step.kind === 'rename') {
        await api.renamePasskey(session.token, step.passkey.id, name.trim());
        reset();
      } else if (step.kind === 'remove') {
        await api.deletePasskey(session.token, step.passkey.id, await reauth(submitted));
        reset();
      } else if (step.kind === 'require') {
        await api.setPasskeyRequired(session.token, step.required, await reauth(submitted));
        reset();
      }
    });
  };

  const needsPassword = step.kind !== 'rename';
  const formLabel =
    step.kind === 'add'
      ? 'Add a passkey'
      : step.kind === 'rename'
        ? 'Rename passkey'
        : step.kind === 'remove'
          ? 'Remove passkey'
          : step.kind === 'require'
            ? step.required
              ? 'Require passkey'
              : 'Stop requiring a passkey'
            : '';
  const submitLabel =
    step.kind === 'add'
      ? 'Create passkey'
      : step.kind === 'rename'
        ? 'Save name'
        : step.kind === 'remove'
          ? 'Remove passkey'
          : step.kind === 'require' && step.required
            ? 'Require passkey'
            : 'Allow authenticator codes again';

  const lastPasskeyWarning =
    step.kind === 'remove' && account && account.passkeys === 1 && !account.totp_enabled;

  return (
    <div className="sheet" role="region" aria-label="Passkeys">
      <h3>Passkeys</h3>
      <p className="hint">
        A passkey is a second factor held by this device, your phone or a security key. It can’t be
        phished: your browser only uses it on this vault’s own address. It guards logging in, like
        an authenticator code; your master password still encrypts the vault.
      </p>
      {!passkeysSupported() && <p className="warning">This browser doesn’t support passkeys.</p>}
      {account === null || passkeys === null ? (
        <p className="quiet-state">Loading…</p>
      ) : step.kind === 'codes' ? (
        <RecoveryCodes codes={step.codes} onDone={() => reset()} />
      ) : step.kind !== 'idle' ? (
        <form onSubmit={submit} aria-label={formLabel}>
          {step.kind === 'remove' && (
            <p>
              Remove <strong>{step.passkey.name}</strong>?{' '}
              {lastPasskeyWarning &&
                'It’s your only second factor, so two-factor login turns off and your recovery codes stop working.'}
            </p>
          )}
          {step.kind === 'require' && (
            <p className="hint">
              {step.required
                ? 'Codes from your authenticator app will stop working for logging in and for account changes; only a passkey or a recovery code will. The browser extension can’t use passkeys, so unlock it with a recovery code or use the web vault.'
                : 'Codes from your authenticator app will work again alongside your passkeys.'}
            </p>
          )}
          {(step.kind === 'add' || step.kind === 'rename') && (
            <label>
              Passkey name
              <input
                required
                maxLength={64}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
          )}
          {needsPassword && (
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
          )}
          {needsPassword && hasSecondFactor(account) && (
            <SecondFactorField
              account={account}
              mode={mode}
              onModeChange={setMode}
              code={code}
              onCodeChange={setCode}
            />
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="row sheet-actions">
            <button
              type="submit"
              className={step.kind === 'remove' ? 'btn btn-danger' : 'btn btn-primary'}
              disabled={busy}
            >
              {busy ? 'Checking…' : submitLabel}
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => reset()}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <>
          {passkeys.length > 0 && (
            <ul className="sessions">
              {passkeys.map((passkey) => (
                <li key={passkey.id} className="session" aria-label={passkey.name}>
                  <div>
                    <strong>{passkey.name}</strong>
                    <p className="hint">
                      Added {formatDate(passkey.created_at)} ·{' '}
                      {passkey.last_used_at
                        ? `last used ${formatDate(passkey.last_used_at)}`
                        : 'not used yet'}
                    </p>
                  </div>
                  <div className="row">
                    <button
                      type="button"
                      className="btn btn-quiet"
                      onClick={() => reset({ kind: 'rename', passkey })}
                    >
                      Rename
                    </button>
                    <button
                      type="button"
                      className="btn btn-quiet"
                      onClick={() => reset({ kind: 'remove', passkey })}
                    >
                      Remove
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {account.passkey_required && (
            <p className="notice" role="status">
              A passkey is required: authenticator codes don’t work for logging in.
            </p>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="row sheet-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!passkeysSupported()}
              onClick={() => reset({ kind: 'add' })}
            >
              Add a passkey
            </button>
            {passkeys.length > 0 && (
              <button
                type="button"
                className="btn"
                onClick={() => reset({ kind: 'require', required: !account.passkey_required })}
              >
                {account.passkey_required
                  ? 'Stop requiring a passkey'
                  : 'Require passkey (turn off authenticator codes for login)'}
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
