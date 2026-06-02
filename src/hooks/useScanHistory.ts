import { useState, useCallback, useEffect, useRef } from 'react';
import type { ScanItem } from '../types/vt';
import type { ScanHistoryEntry } from '../types/api';
import { api } from '../lib/api';
import { useAuthState } from '../context/AuthContext';

// Scan history is durable + per-user in Supabase (see api/scan-history.js).
// When logged out / the API is unreachable we fall back to localStorage so the
// tab still works offline. `LS_IMPORTED_KEY` flags that the one-time migration
// of any pre-cloud localStorage history has already run.
const LS_KEY = 'socToolboxScanHistory';
const LS_IMPORTED_KEY = 'socToolboxScanHistoryImported';
const MAX = 50;

export interface HistoryEntry {
  id: string;
  ts: string;
  input: string;
  count: number;
  items: ScanItem[];
}

// Map a Supabase row to the shape HistoryTab already consumes (created_at → ts).
function fromServer(row: ScanHistoryEntry): HistoryEntry {
  return { id: row.id, ts: row.created_at, input: row.input, count: row.count, items: row.items ?? [] };
}

function loadLocal(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveLocal(entries: HistoryEntry[]) {
  try { localStorage.setItem(LS_KEY, JSON.stringify(entries.slice(0, MAX))); } catch { /* ignore quota */ }
}

export function useScanHistory() {
  const { ready, authed } = useAuthState();
  const cloud = ready && authed;
  const [entries, setEntries] = useState<HistoryEntry[]>(loadLocal);
  const [search, setSearch] = useState('');
  const importedRef = useRef(false);

  // Once authenticated: run the one-time localStorage→cloud import, then load
  // the user's cloud history. On any failure we keep the localStorage view.
  useEffect(() => {
    if (!cloud) return;
    let cancelled = false;

    (async () => {
      if (!importedRef.current && localStorage.getItem(LS_IMPORTED_KEY) !== '1') {
        importedRef.current = true;
        // Claim the import synchronously so a second hook instance (or reload)
        // can't run it again and create duplicates.
        try { localStorage.setItem(LS_IMPORTED_KEY, '1'); } catch { /* ignore */ }
        // Oldest first so cloud created_at order matches the original sequence.
        for (const e of [...loadLocal()].reverse()) {
          try { await api.history.add(e.input, e.count, e.items); } catch { /* best-effort */ }
        }
        try { localStorage.removeItem(LS_KEY); } catch { /* ignore */ }
      }

      try {
        const res = await api.history.list(MAX);
        if (!cancelled) setEntries(res.entries.map(fromServer));
      } catch { /* keep local fallback view */ }
    })();

    return () => { cancelled = true; };
  }, [cloud]);

  const addEntry = useCallback(async (input: string, items: ScanItem[]) => {
    const count = items.length;
    // Optimistic insert so the entry shows immediately; also the offline record.
    const optimistic: HistoryEntry = {
      id: `tmp-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      ts: new Date().toISOString(),
      input, count, items,
    };
    setEntries(prev => {
      const next = [optimistic, ...prev].slice(0, MAX);
      if (!cloud) saveLocal(next);
      return next;
    });

    if (!cloud) return;
    try {
      const res = await api.history.add(input, count, items);
      // Swap the temp row for the persisted one (real id + server timestamp).
      setEntries(prev => prev.map(e => (e.id === optimistic.id ? fromServer(res.entry) : e)));
    } catch {
      // Cloud write failed → keep the optimistic entry and persist it locally.
      setEntries(prev => { saveLocal(prev); return prev; });
    }
  }, [cloud]);

  const removeEntry = useCallback(async (id: string) => {
    setEntries(prev => {
      const next = prev.filter(e => e.id !== id);
      if (!cloud) saveLocal(next);
      return next;
    });
    if (cloud) { try { await api.history.remove(id); } catch { /* ignore */ } }
  }, [cloud]);

  const clearAll = useCallback(async () => {
    setEntries([]);
    if (cloud) { try { await api.history.clear(); } catch { /* ignore */ } }
    else { try { localStorage.removeItem(LS_KEY); } catch { /* ignore */ } }
  }, [cloud]);

  const filtered = search.trim()
    ? entries.filter(e => e.input.toLowerCase().includes(search.toLowerCase()))
    : entries;

  return { entries: filtered, allEntries: entries, search, setSearch, addEntry, removeEntry, clearAll };
}
