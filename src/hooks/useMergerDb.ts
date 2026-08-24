import { useState, useCallback, useEffect, useRef } from 'react';
import { api } from '../lib/api';
import { extractIOC, detectType } from '../lib/ioc';
import type { Team } from '../types/api';

const CHUNK = 40;

export interface MergerItem {
  ip: string;
  payload: Record<string, unknown>;
  updated_at: string;
}

/** Session cache — identity + team scoped so logout/login never leaks prior snapshots. */
const sessionItems: Record<string, MergerItem[]> = {};
const sessionAutoFetched: Record<string, boolean> = {};

export function invalidateMergerDbCache(identity: string, team: Team, clientCode?: string) {
  const cacheKey = `${identity}:${team}:${clientCode ?? 'LEGACY'}`;
  delete sessionItems[cacheKey];
  delete sessionAutoFetched[cacheKey];
}

export function useMergerDb(team: Team, identity: string, clientCode?: string) {
  const cacheKey = `${identity}:${team}:${clientCode ?? 'LEGACY'}`;
  const [items, setItems] = useState<MergerItem[]>(() => sessionItems[cacheKey] ?? []);
  const [loading, setLoading] = useState(false);
  const [posting, setPosting] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const submitInFlight = useRef(false);
  const deleteInFlight = useRef(false);
  const activeCacheKey = useRef(cacheKey);
  activeCacheKey.current = cacheKey;

  const refresh = useCallback(async () => {
    const requestCacheKey = cacheKey;
    setLoading(true);
    setError(null);
    try {
      const res = await api.teamFilter.get(team, clientCode);
      const loaded = res.items ?? [];
      sessionItems[cacheKey] = loaded;
      sessionAutoFetched[cacheKey] = true;
      if (activeCacheKey.current === requestCacheKey) {
        setItems(loaded);
        setStatusMsg(`✓ ${loaded.length} IPs loaded from DB.`);
      }
      return loaded;
    } catch (err) {
      if (activeCacheKey.current === requestCacheKey) setError(err instanceof Error ? err.message : String(err));
      return null;
    } finally {
      if (activeCacheKey.current === requestCacheKey) setLoading(false);
    }
  }, [cacheKey, team, clientCode]);

  // Auto-fetch once per identity and team; never reuse another user's rows.
  useEffect(() => {
    setItems(sessionItems[cacheKey] ?? []);
    if (sessionAutoFetched[cacheKey]) {
      setItems(sessionItems[cacheKey]);
      return;
    }
    refresh();
  }, [cacheKey, refresh]);

  const submitIps = useCallback(async (rawInput: string): Promise<boolean> => {
    // React state updates on the next render. Ref locks synchronously so rapid clicks
    // cannot start duplicate requests before `posting` disables the button.
    if (submitInFlight.current) return false;
    submitInFlight.current = true;

    try {
      const lines = rawInput.split('\n').map(s => extractIOC(s)).filter(s => s && detectType(s) === 'ip' && !s.includes(':'));
      const unique = [...new Set(lines)];
      const existing = new Set(items.map(i => i.ip));
      const toPost = unique.filter(ip => !existing.has(ip));

      if (!toPost.length) {
        setStatusMsg('No new IPs (all already in DB).');
        return false;
      }

      setPosting(true);
      setProgress({ done: 0, total: toPost.length });
      setError(null);

      const chunks: string[][] = [];
      for (let i = 0; i < toPost.length; i += CHUNK) {
        chunks.push(toPost.slice(i, i + CHUNK));
      }

      let done = 0;
      for (const chunk of chunks) {
        try {
          await api.teamFilter.post(team, chunk, clientCode);
          done += chunk.length;
          setProgress({ done, total: toPost.length });
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err));
          break;
        }
      }

      if (done > 0) {
        const loaded = await refresh();
        if (loaded) {
          setStatusMsg(`✓ ${done} IPs submitted. Latest data loaded (${loaded.length} IPs in DB).`);
        }
        return done === toPost.length && loaded !== null;
      }
      return false;
    } finally {
      submitInFlight.current = false;
      setPosting(false);
      setProgress(null);
    }
  }, [items, refresh, team, clientCode]);

  const deleteIps = useCallback(async (ips: string[]): Promise<boolean> => {
    if (deleteInFlight.current) return false;
    deleteInFlight.current = true;
    setLoading(true);
    setError(null);
    let deleted = 0;
    try {
      for (let i = 0; i < ips.length; i += CHUNK) {
        const res = await api.teamFilter.delete(team, ips.slice(i, i + CHUNK), clientCode);
        deleted += res.deletedCount ?? 0;
      }
      // Always refresh from DB — if delete silently matched 0 rows (normalization
      // mismatch, stale session cache, etc.) the IPs reappear instead of being
      // ghost-removed from the UI while still in the database.
      const loaded = await refresh();
      if (!loaded) return false;
      if (deleted === 0) {
        setStatusMsg('⚠ 0 IPs deleted — DB did not match. Reloaded from DB.');
      } else if (deleted < ips.length) {
        setStatusMsg(`⚠ ${deleted}/${ips.length} IPs deleted. Some not in DB. Reloaded.`);
      } else {
        setStatusMsg(`✓ ${deleted} IPs deleted from DB.`);
      }
      return deleted === ips.length;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (deleted > 0) await refresh();
      setError(message);
      return false;
    } finally {
      deleteInFlight.current = false;
      setLoading(false);
    }
  }, [refresh, team, clientCode]);

  const clearStatus = useCallback(() => {
    setError(null);
    setStatusMsg(null);
  }, []);

  return {
    items,
    itemCount: items.length,
    loading,
    posting,
    progress,
    error,
    statusMsg,
    setStatusMsg,
    clearStatus,
    refresh,
    submitIps,
    deleteIps,
  };
}
