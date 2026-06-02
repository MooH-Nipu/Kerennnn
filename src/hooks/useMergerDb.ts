import { useState, useCallback, useEffect } from 'react';
import { api } from '../lib/api';
import { extractIOC, detectType } from '../lib/ioc';

const CHUNK = 40;

export interface MergerItem {
  ip: string;
  payload: Record<string, unknown>;
  updated_at: string;
}

/** Session cache — survives tab unmount (persists last-loaded merger rows across remounts). */
let sessionItems: MergerItem[] = [];
let sessionAutoFetched = false;

function syncSession(items: MergerItem[]) {
  sessionItems = items;
}

export function useMergerDb() {
  const [items, setItems] = useState<MergerItem[]>(() => sessionItems);
  const [loading, setLoading] = useState(false);
  const [posting, setPosting] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.mergerDb.get() as { items?: MergerItem[] };
      const loaded = res.items ?? [];
      syncSession(loaded);
      setItems(loaded);
      sessionAutoFetched = true;
      setStatusMsg(`✓ ${loaded.length} IP dimuat dari DB.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-fetch once per session on first mount; later visits reuse sessionItems.
  useEffect(() => {
    if (sessionAutoFetched) {
      setItems(sessionItems);
      return;
    }
    refresh();
  }, [refresh]);

  const submitIps = useCallback(async (rawInput: string) => {
    const lines = rawInput.split('\n').map(s => extractIOC(s)).filter(s => s && detectType(s) === 'ip');
    const unique = [...new Set(lines)];
    const existing = new Set(items.map(i => i.ip));
    const toPost = unique.filter(ip => !existing.has(ip));

    if (!toPost.length) {
      setStatusMsg('Tidak ada IP baru (semua sudah ada di DB).');
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
        await api.mergerDb.post(chunk);
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
      setStatusMsg(`✓ ${done} IP dikirim. Data terbaru dimuat (${sessionItems.length} IP di DB).`);
    }
  }, [items, refresh]);

  const deleteIps = useCallback(async (ips: string[]) => {
    setLoading(true);
    setError(null);
    try {
      await api.mergerDb.delete(ips);
      setItems(prev => {
        const next = prev.filter(i => !ips.includes(i.ip));
        syncSession(next);
        return next;
      });
      setStatusMsg(`✓ ${ips.length} IP dihapus.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
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
    refresh,
    submitIps,
    deleteIps,
  };
}
