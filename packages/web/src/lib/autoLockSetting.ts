import { useCallback, useState } from 'react';

export const AUTO_LOCK_OPTIONS_MINUTES = [1, 5, 15, 30, 60] as const;
export const DEFAULT_AUTO_LOCK_MINUTES = 5;

// A non-secret preference, so localStorage is fine for it.
const STORAGE_KEY = 'password-manager.autoLockMinutes';

function readSetting(): number {
  try {
    const stored = Number(localStorage.getItem(STORAGE_KEY));
    return (AUTO_LOCK_OPTIONS_MINUTES as readonly number[]).includes(stored)
      ? stored
      : DEFAULT_AUTO_LOCK_MINUTES;
  } catch {
    return DEFAULT_AUTO_LOCK_MINUTES;
  }
}

export function useAutoLockSetting(): [number, (minutes: number) => void] {
  const [minutes, setMinutes] = useState(readSetting);
  const update = useCallback((value: number) => {
    setMinutes(value);
    try {
      localStorage.setItem(STORAGE_KEY, String(value));
    } catch {
      // Storage unavailable (private mode): keep the in-memory value.
    }
  }, []);
  return [minutes, update];
}
