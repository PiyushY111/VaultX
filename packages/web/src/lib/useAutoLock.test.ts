import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAutoLock } from './useAutoLock';

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

const advance = (ms: number) => act(() => vi.advanceTimersByTime(ms));

describe('useAutoLock', () => {
  it('locks once after the timeout with no activity', () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock({ enabled: true, timeoutMs: 60_000, onLock }));
    advance(59_000);
    expect(onLock).not.toHaveBeenCalled();
    advance(2_000);
    expect(onLock).toHaveBeenCalledOnce();
    advance(120_000);
    expect(onLock).toHaveBeenCalledOnce();
  });

  it.each(['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart', 'scroll'])(
    'resets the timer on %s',
    (eventName) => {
      const onLock = vi.fn();
      renderHook(() => useAutoLock({ enabled: true, timeoutMs: 60_000, onLock }));
      advance(50_000);
      act(() => {
        window.dispatchEvent(new Event(eventName));
      });
      advance(50_000);
      expect(onLock).not.toHaveBeenCalled();
      advance(11_000);
      expect(onLock).toHaveBeenCalledOnce();
    },
  );

  it('locks immediately on return if the wall clock jumped (e.g. laptop sleep)', () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock({ enabled: true, timeoutMs: 60_000, onLock }));
    // Timers don't fire while asleep; only the clock moves.
    vi.setSystemTime(Date.now() + 10 * 60_000);
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(onLock).toHaveBeenCalledOnce();
  });

  it('does nothing while disabled', () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock({ enabled: false, timeoutMs: 1_000, onLock }));
    advance(60_000);
    expect(onLock).not.toHaveBeenCalled();
  });

  it('stops when unmounted', () => {
    const onLock = vi.fn();
    const { unmount } = renderHook(() => useAutoLock({ enabled: true, timeoutMs: 1_000, onLock }));
    unmount();
    advance(60_000);
    expect(onLock).not.toHaveBeenCalled();
  });
});
