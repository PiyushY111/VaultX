import { useEffect, useRef } from 'react';

const ACTIVITY_EVENTS = [
  'pointerdown',
  'pointermove',
  'keydown',
  'wheel',
  'touchstart',
  'scroll',
] as const;
const CHECK_INTERVAL_MS = 1000;

/**
 * Calls `onLock` once `timeoutMs` passes without user activity. Elapsed time
 * is measured with the wall clock rather than a single timer, so a sleeping
 * laptop or a throttled background tab still locks on return.
 */
export function useAutoLock({
  enabled,
  timeoutMs,
  onLock,
}: {
  enabled: boolean;
  timeoutMs: number;
  onLock: () => void;
}): void {
  const onLockRef = useRef(onLock);
  useEffect(() => {
    onLockRef.current = onLock;
  }, [onLock]);

  useEffect(() => {
    if (!enabled) return;
    let lastActivity = Date.now();
    let locked = false;
    const recordActivity = () => {
      lastActivity = Date.now();
    };
    const check = () => {
      if (!locked && Date.now() - lastActivity >= timeoutMs) {
        locked = true;
        onLockRef.current();
      }
    };

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, recordActivity, { capture: true, passive: true });
    }
    document.addEventListener('visibilitychange', check);
    const interval = window.setInterval(check, CHECK_INTERVAL_MS);

    return () => {
      for (const event of ACTIVITY_EVENTS)
        window.removeEventListener(event, recordActivity, { capture: true });
      document.removeEventListener('visibilitychange', check);
      window.clearInterval(interval);
    };
  }, [enabled, timeoutMs]);
}
