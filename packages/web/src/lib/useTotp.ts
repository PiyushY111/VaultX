import { parseTotp, totpCode, type TotpConfig } from '@password-manager/crypto';
import { useEffect, useMemo, useState } from 'react';

export type TotpState =
  | { kind: 'none' }
  | { kind: 'invalid'; message: string }
  | { kind: 'code'; code: string; secondsLeft: number; period: number; config: TotpConfig };

/** Reads a setup key or otpauth:// link; null if empty, a message if it's not valid. */
export function readTotp(input: string): TotpConfig | string | null {
  if (!input.trim()) return null;
  try {
    return parseTotp(input);
  } catch (error) {
    return error instanceof Error ? error.message : 'That setup key isn’t valid.';
  }
}

/** The current code for a TOTP secret, updated every second. */
export function useTotp(input: string | undefined): TotpState {
  const parsed = useMemo(() => readTotp(input ?? ''), [input]);
  const [state, setState] = useState<TotpState>({ kind: 'none' });

  useEffect(() => {
    if (parsed === null) return setState({ kind: 'none' });
    if (typeof parsed === 'string') return setState({ kind: 'invalid', message: parsed });
    let active = true;
    const update = () =>
      totpCode(parsed).then(({ code, secondsLeft }) => {
        if (active)
          setState({ kind: 'code', code, secondsLeft, period: parsed.period, config: parsed });
      });
    void update();
    const timer = setInterval(() => void update(), 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [parsed]);

  return state;
}

/** 123456 → "123 456", as authenticator apps show codes. */
export const groupDigits = (code: string) => code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2');
