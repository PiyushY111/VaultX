import type { ReactNode } from 'react';
import { Emblem } from './Emblem';

interface Props {
  /** Show the "Locked" stamp: the vault was locked, not just logged out. */
  sealed: boolean;
  children: ReactNode;
}

/**
 * Split screen for login, sign-up and unlock. The left wall is a storehouse
 * wall: a diagonal plaster lattice with the emblem set into it. It's
 * decorative, so it's hidden from assistive tech.
 */
export function AuthLayout({ sealed, children }: Props) {
  return (
    <div className="auth">
      <div className="wall" aria-hidden="true">
        <Emblem className="wall-mark" />
        <span className="wall-name">VaultX</span>
        {sealed && <span className="stamp">Locked</span>}
      </div>
      <main className="auth-panel">
        <h1 className="brand">VaultX</h1>
        {children}
      </main>
    </div>
  );
}
