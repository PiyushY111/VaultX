import { useCallback, useRef, useState } from 'react';
import { AuthLayout } from './components/AuthLayout';
import { LoginForm } from './components/LoginForm';
import { SignupForm } from './components/SignupForm';
import { VaultView } from './components/VaultView';
import { useAutoLockSetting } from './lib/autoLockSetting';
import { useAutoLock } from './lib/useAutoLock';
import { lockSession, type VaultSession } from './vault/session';

type Screen =
  | { kind: 'login' }
  | { kind: 'signup' }
  | { kind: 'locked'; email: string }
  | { kind: 'vault'; session: VaultSession };

export function App() {
  const [screen, setScreen] = useState<Screen>({ kind: 'login' });
  const [notice, setNotice] = useState<string | null>(null);
  const [autoLockMinutes, setAutoLockMinutes] = useAutoLockSetting();
  const sessionRef = useRef<VaultSession | null>(null);

  const openVault = useCallback((session: VaultSession) => {
    sessionRef.current = session;
    setNotice(null);
    setScreen({ kind: 'vault', session });
  }, []);

  // Wipes the vault key and token, and unmounts the vault view so every
  // decrypted item in its state is dropped. Only the email is kept, to
  // prefill the unlock form.
  const lock = useCallback((reason?: string) => {
    const session = sessionRef.current;
    if (!session) return;
    sessionRef.current = null;
    lockSession(session);
    // Only explain locks the user didn't trigger (inactivity, expired session).
    setNotice(reason ?? null);
    setScreen({ kind: 'locked', email: session.email });
  }, []);

  const logOut = useCallback(() => {
    const session = sessionRef.current;
    if (session) lockSession(session);
    sessionRef.current = null;
    setNotice(null);
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
        <LoginForm onUnlocked={openVault} onSwitchToSignup={() => setScreen({ kind: 'signup' })} />
      )}
      {screen.kind === 'signup' && (
        <SignupForm onSignedUp={openVault} onSwitchToLogin={() => setScreen({ kind: 'login' })} />
      )}
      {screen.kind === 'locked' && (
        <LoginForm
          lockedEmail={screen.email}
          onUnlocked={openVault}
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
