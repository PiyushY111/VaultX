import { useCallback, useEffect, useState } from 'react';
import { ApiError, api, type AccountInfo, type Reauth } from '../api';
import { downloadText } from '../lib/download';
import { getPasskeyAssertion } from '../lib/passkeys';
import type { VaultSession } from '../vault/session';

/** A 6-digit code from the app, or anything else as a recovery code. */
export function secondFactorOf(code: string): Partial<Reauth> {
  const trimmed = code.trim();
  if (!trimmed) return {};
  return /^\d{6}$/.test(trimmed) ? { totp_code: trimmed } : { recovery_code: trimmed };
}

export function useAccount(session: VaultSession, onSessionExpired: () => void) {
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

export const hasSecondFactor = (account: AccountInfo | null): boolean =>
  Boolean(account && (account.totp_enabled || account.passkeys > 0));

/** TOTP codes count for re-authentication unless "Require passkey" is on. */
const totpAccepted = (account: AccountInfo) => account.totp_enabled && !account.passkey_required;

export type FactorMode = 'passkey' | 'code';

export const defaultFactorMode = (account: AccountInfo | null): FactorMode =>
  account && account.passkeys > 0 ? 'passkey' : 'code';

/**
 * The second factor for a re-authentication: a passkey (signed right away,
 * against a fresh challenge from the server) or the code typed in.
 */
export async function resolveSecondFactor(
  session: VaultSession,
  mode: FactorMode,
  code: string,
): Promise<Partial<Reauth>> {
  if (mode === 'code') return secondFactorOf(code);
  const { options } = await api.passkeyReauthOptions(session.token);
  return { webauthn: await getPasskeyAssertion(options) };
}

/**
 * Asks for one of the account's existing second factors: a passkey if it has
 * one (with a switch to a code), otherwise a code from the app or a
 * recovery code.
 */
export function SecondFactorField({
  account,
  mode,
  onModeChange,
  code,
  onCodeChange,
}: {
  account: AccountInfo;
  mode: FactorMode;
  onModeChange: (mode: FactorMode) => void;
  code: string;
  onCodeChange: (code: string) => void;
}) {
  const label = totpAccepted(account) ? 'Code from your app, or a recovery code' : 'Recovery code';
  return (
    <div className="second-factor-field">
      {mode === 'passkey' ? (
        <p className="hint">You’ll confirm with your passkey when you continue.</p>
      ) : (
        <label>
          {label}
          <input
            autoComplete="one-time-code"
            required
            value={code}
            onChange={(e) => onCodeChange(e.target.value)}
          />
        </label>
      )}
      {account.passkeys > 0 && (
        <button
          type="button"
          className="link"
          onClick={() => {
            onCodeChange('');
            onModeChange(mode === 'passkey' ? 'code' : 'passkey');
          }}
        >
          {mode === 'passkey' ? `Use a ${label.toLowerCase()} instead` : 'Use a passkey instead'}
        </button>
      )}
    </div>
  );
}

export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = [
    'VaultX two-factor recovery codes',
    '',
    'Each code works once, instead of a passkey or a code from your authenticator app.',
    '',
    ...codes,
    '',
  ].join('\n');
  return (
    <div className="recovery" role="region" aria-label="Recovery codes">
      <p className="warning">
        Save these recovery codes somewhere safe. Each one lets you log in once without your passkey
        or authenticator app. They won’t be shown again.
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
