import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';
import { useAuthState } from '../context/AuthContext';
import type { TabId } from '../lib/permissions';

// Per-user tab-bar customization (order + hidden tabs).
// Cloud-first (Supabase `user_prefs`, synced across devices) with a localStorage
// mirror for instant paint + offline/logged-out fallback. Mirrors the
// cloud+local pattern used by useScanHistory.

const LS_PREFIX = 'socToolboxTabPrefs';

export interface TabPrefsState {
  order: TabId[];
  hidden: TabId[];
}

const EMPTY: TabPrefsState = { order: [], hidden: [] };

function lsKey(username: string | null | undefined) {
  return username ? `${LS_PREFIX}_${username}` : LS_PREFIX;
}

function readLs(username: string | null | undefined): TabPrefsState {
  try {
    const raw = localStorage.getItem(lsKey(username));
    if (raw) {
      const p = JSON.parse(raw) as Partial<TabPrefsState>;
      return {
        order: Array.isArray(p.order) ? (p.order as TabId[]) : [],
        hidden: Array.isArray(p.hidden) ? (p.hidden as TabId[]) : [],
      };
    }
  } catch { /* ignore corrupt/blocked storage */ }
  return EMPTY;
}

function writeLs(username: string | null | undefined, s: TabPrefsState) {
  try { localStorage.setItem(lsKey(username), JSON.stringify(s)); } catch { /* ignore */ }
}

export function useTabPrefs() {
  const { ready, authed, username } = useAuthState();
  const [prefs, setPrefs] = useState<TabPrefsState>(EMPTY);
  const loadedFor = useRef<string | null>(null);

  useEffect(() => {
    if (!ready) return;
    const key = authed ? `cloud:${username}` : 'local';
    if (loadedFor.current === key) return;
    loadedFor.current = key;

    // Instant paint from localStorage…
    setPrefs(readLs(username));

    // …then reconcile with the cloud (source of truth when logged in).
    if (authed) {
      api.userPrefs.get()
        .then(res => {
          const next: TabPrefsState = {
            order: (res.tab_order ?? []) as TabId[],
            hidden: (res.hidden_tabs ?? []) as TabId[],
          };
          setPrefs(next);
          writeLs(username, next);
        })
        .catch(() => { /* offline / not configured → keep localStorage copy */ });
    }
  }, [ready, authed, username]);

  const save = useCallback((order: TabId[], hidden: TabId[]) => {
    const next: TabPrefsState = { order, hidden };
    setPrefs(next);                 // optimistic
    writeLs(username, next);
    if (authed) {
      api.userPrefs.save(order, hidden).catch(() => { /* best-effort; LS already updated */ });
    }
  }, [authed, username]);

  const reset = useCallback(() => save([], []), [save]);

  return { order: prefs.order, hidden: prefs.hidden, save, reset };
}
