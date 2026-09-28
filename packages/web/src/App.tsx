import { useCallback, useRef, useState } from 'react';
import { AuthLayout } from './components/AuthLayout';
import { LoginForm } from './components/LoginForm';
import { SignupForm } from './components/SignupForm';
import { VaultView } from './components/VaultView';
import { useAutoLockSetting } from './lib/autoLockSetting';
import { clearCopiedSecretNow } from './lib/clipboard';
import { useAutoLock } from './lib/useAutoLock';
import { revisionStorageKey } from './vault/revisionLedger';
import { lockSession, type VaultSession } from './vault/session';

type Screen =
  | { kind: 'login' }
  | { kind: 'signup' }
  | { kind: 'locked'; email: string }
  | { kind: 'vault'; session: VaultSession; justSignedUp?: boolean };

export function App() {
  const [screen, setScreen] = useState<Screen>({ kind: 'login' });
  const [notice, setNotice] = useState<string | null>(null);
  const [autoLockMinutes, setAutoLockMinutes] = useAutoLockSetting();
  const sessionRef = useRef<VaultSession | null>(null);

  const openVault = useCallback((session: VaultSession, justSignedUp = false) => {
    sessionRef.current = session;
    setNotice(null);
    setScreen({ kind: 'vault', session, justSignedUp });
  }, []);

  // Wipes the vault key and token, ends the server session, clears a copied
  // password, and unmounts the vault view so every decrypted item in its
  // state is dropped. Only the email is kept, to prefill the unlock form.
  const lock = useCallback((reason?: string) => {
    const session = sessionRef.current;
    if (!session) return;
    sessionRef.current = null;
    lockSession(session);
    clearCopiedSecretNow();
    // Only explain locks the user didn't trigger (inactivity, expired session).
    setNotice(reason ?? null);
    setScreen({ kind: 'locked', email: session.email });
  }, []);

  const logOut = useCallback(() => {
    const session = sessionRef.current;
    if (session) lockSession(session);
    clearCopiedSecretNow();
    sessionRef.current = null;
    setNotice(null);
    setScreen({ kind: 'login' });
  }, []);

  const accountDeleted = useCallback(() => {
    const session = sessionRef.current;
    if (session) {
      lockSession(session);
      try {
        localStorage.removeItem(revisionStorageKey(session.email));
      } catch {
        // Nothing to clean up.
      }
    }
    clearCopiedSecretNow();
    sessionRef.current = null;
    setNotice('Your account and everything in your vault were deleted.');
    setScreen({ kind: 'login' });
  }, []);

  useAutoLock({
    enabled: screen.kind === 'vault',
    timeoutMs: autoLockMinutes * 60_000,
    onLock: () =>
      lock(
        `Locked after ${autoLockMinutes} minute${autoLockMinutes === 1 ? '' : 's'} of inactivity.`,
      ),
  });

  if (screen.kind === 'vault') {
    return (
      <VaultView
        session={screen.session}
        autoLockMinutes={autoLockMinutes}
        onChangeAutoLock={setAutoLockMinutes}
        onLock={lock}
        onLogOut={logOut}
        onAccountDeleted={accountDeleted}
        justSignedUp={screen.justSignedUp ?? false}
      />
    );
  }

  return (
    <AuthLayout sealed={screen.kind === 'locked'}>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {screen.kind === 'login' && (
        <LoginForm
          onUnlocked={(session) => openVault(session)}
          onSwitchToSignup={() => setScreen({ kind: 'signup' })}
        />
      )}
      {screen.kind === 'signup' && (
        <SignupForm
          onSignedUp={(session) => openVault(session, true)}
          onSwitchToLogin={() => setScreen({ kind: 'login' })}
        />
      )}
      {screen.kind === 'locked' && (
        <LoginForm
          lockedEmail={screen.email}
          onUnlocked={(session) => openVault(session)}
          onSwitchToSignup={() => setScreen({ kind: 'signup' })}
          onSwitchAccount={() => {
            setNotice(null);
            setScreen({ kind: 'login' });
          }}
        />
      )}
    </AuthLayout>
  );
}
