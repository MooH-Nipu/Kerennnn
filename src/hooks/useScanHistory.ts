import { useState, useCallback } from 'react';
import type { ScanItem } from '../types/vt';

const LS_KEY = 'socToolboxScanHistory';
const MAX = 20;

export interface HistoryEntry {
  id: string;
  ts: string;
  input: string;
  count: number;
  items: ScanItem[];
}

function load(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function save(entries: HistoryEntry[]) {
  localStorage.setItem(LS_KEY, JSON.stringify(entries.slice(0, MAX)));
}

export function useScanHistory() {
  const [entries, setEntries] = useState<HistoryEntry[]>(load);
  const [search, setSearch] = useState('');

  const addEntry = useCallback((input: string, items: ScanItem[]) => {
    const entry: HistoryEntry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      ts: new Date().toISOString(),
      input,
      count: items.length,
      items,
    };
    setEntries(prev => {
      const next = [entry, ...prev].slice(0, MAX);
      save(next);
      return next;
    });
  }, []);

  const removeEntry = useCallback((id: string) => {
    setEntries(prev => {
      const next = prev.filter(e => e.id !== id);
      save(next);
      return next;
    });
  }, []);

  const clearAll = useCallback(() => {
    localStorage.removeItem(LS_KEY);
    setEntries([]);
  }, []);

  const filtered = search.trim()
    ? entries.filter(e => e.input.toLowerCase().includes(search.toLowerCase()))
    : entries;

  return { entries: filtered, allEntries: entries, search, setSearch, addEntry, removeEntry, clearAll };
}
