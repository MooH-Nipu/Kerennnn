import { useEffect, useRef, useCallback } from 'react';

export function useAutoRefresh(fn: () => void, intervalMs: number, enabled: boolean) {
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(() => {
    fnRef.current();
  }, []);

  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => fnRef.current(), intervalMs);
    return () => clearInterval(id);
  }, [enabled, intervalMs]);

  return { refresh: run };
}
