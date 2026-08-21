import { useState, useCallback, useEffect } from 'react';
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

export function useMergerDb(team: Team, identity: string) {
  const cacheKey = `${identity}:${team}`;
  const [items, setItems] = useState<MergerItem[]>(() => sessionItems[cacheKey] ?? []);
  const [loading, setLoading] = useState(false);
  const [posting, setPosting] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.teamFilter.get(team);
      const loaded = res.items ?? [];
      sessionItems[cacheKey] = loaded;
      setItems(loaded);
      sessionAutoFetched[cacheKey] = true;
      setStatusMsg(`✓ ${loaded.length} IPs loaded from DB.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [cacheKey, team]);

  // Auto-fetch once per identity and team; never reuse another user's rows.
  useEffect(() => {
    if (sessionAutoFetched[cacheKey]) {
      setItems(sessionItems[cacheKey]);
      return;
    }
    refresh();
  }, [cacheKey, refresh]);

  const submitIps = useCallback(async (rawInput: string) => {
    const lines = rawInput.split('\n').map(s => extractIOC(s)).filter(s => s && detectType(s) === 'ip' && !s.includes(':'));
    const unique = [...new Set(lines)];
    const existing = new Set(items.map(i => i.ip));
    const toPost = unique.filter(ip => !existing.has(ip));

    if (!toPost.length) {
      setStatusMsg('No new IPs (all already in DB).');
      return;
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
        await api.teamFilter.post(team, chunk);
        done += chunk.length;
        setProgress({ done, total: toPost.length });
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        break;
      }
    }

    setPosting(false);
    setProgress(null);

    if (done > 0) {
      await refresh();
      setStatusMsg(`✓ ${done} IPs submitted. Latest data loaded (${sessionItems[cacheKey].length} IPs in DB).`);
    }
  }, [cacheKey, items, refresh, team]);

  const deleteIps = useCallback(async (ips: string[]) => {
    setLoading(true);
    setError(null);
    try {
      let deleted = 0;
      for (let i = 0; i < ips.length; i += CHUNK) {
        const res = await api.teamFilter.delete(team, ips.slice(i, i + CHUNK));
        deleted += res.deletedCount ?? 0;
      }
      // Always refresh from DB — if delete silently matched 0 rows (normalization
      // mismatch, stale session cache, etc.) the IPs reappear instead of being
      // ghost-removed from the UI while still in the database.
      await refresh();
      if (deleted === 0) {
        setStatusMsg('⚠ 0 IPs deleted — DB did not match. Reloaded from DB.');
      } else if (deleted < ips.length) {
        setStatusMsg(`⚠ ${deleted}/${ips.length} IPs deleted. Some not in DB. Reloaded.`);
      } else {
        setStatusMsg(`✓ ${deleted} IPs deleted from DB.`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [refresh, team]);

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
