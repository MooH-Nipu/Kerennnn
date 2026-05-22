import { useState, useCallback } from 'react';
import { api } from '../lib/api';
import { extractIOC, detectType } from '../lib/ioc';

const CHUNK = 40;
const LS_PW_KEY = 'socToolboxMergerPassword';

export interface MergerItem {
  ip: string;
  payload: Record<string, unknown>;
  updated_at: string;
}

export function useMergerDb() {
  const [items, setItems] = useState<MergerItem[]>([]);
  const [password, setPassword] = useState<string>(() => localStorage.getItem(LS_PW_KEY) ?? '');
  const [loading, setLoading] = useState(false);
  const [posting, setPosting] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  function savePassword(pw: string) {
    setPassword(pw);
    if (pw) localStorage.setItem(LS_PW_KEY, pw);
    else localStorage.removeItem(LS_PW_KEY);
  }

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.mergerDb.get(password || undefined) as { items?: MergerItem[] };
      setItems(res.items ?? []);
      setStatusMsg(`✓ ${(res.items ?? []).length} IP dimuat dari DB.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [password]);

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
        await api.mergerDb.post(chunk, password || undefined);
        done += chunk.length;
        setProgress({ done, total: toPost.length });
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        break;
      }
    }

    setPosting(false);
    setProgress(null);
    setStatusMsg(`✓ ${done} IP dikirim. Klik Refresh untuk melihat data terbaru.`);
  }, [items, password]);

  const deleteIps = useCallback(async (ips: string[]) => {
    setLoading(true);
    setError(null);
    try {
      await api.mergerDb.delete(ips, password || undefined);
      setItems(prev => prev.filter(i => !ips.includes(i.ip)));
      setStatusMsg(`✓ ${ips.length} IP dihapus.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [password]);

  return {
    items,
    itemCount: items.length,
    password,
    savePassword,
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
