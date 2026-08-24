import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';
import { useAuthState } from '../context/AuthContext';
import type { TabId } from '../lib/permissions';

export type TabSectionId = string;

export interface NavGroup {
  id: string;
  label: string;
  tabs: TabId[];
}

export const DEFAULT_NAV_LAYOUT: NavGroup[] = [
  { id: 'work', label: 'Work', tabs: ['ioc-scan', 'history', 'ir-manager'] },
  { id: 'operations', label: 'Operations', tabs: ['pac-filter', 'daily-eod'] },
  { id: 'utilities', label: 'Utilities', tabs: ['formatter', 'merger', 'json', 'cve', 'attack'] },
  { id: 'admin', label: 'Admin', tabs: ['dashboard', 'admin-usage', 'admin-users', 'admin-logs'] },
];
export const L1_NAV_LAYOUT: NavGroup[] = [
  { id: 'work', label: 'Investigation', tabs: ['ioc-scan', 'history', 'ir-manager'] },
  { id: 'operations', label: 'Operations', tabs: ['pac-filter', 'daily-eod'] },
  { id: 'utilities', label: 'Utilities', tabs: ['formatter', 'merger', 'json', 'cve', 'attack'] },
];

export interface TabPrefsState {
  hidden: TabId[];
  tabLabels: Partial<Record<TabId, string>>;
  groupLabels: Partial<Record<TabSectionId, string>>;
  layout: NavGroup[];
  tutorialDismissed: boolean;
}

const LS_PREFIX = 'socToolboxTabPrefs';
const EMPTY: TabPrefsState = { hidden: [], tabLabels: {}, groupLabels: {}, layout: DEFAULT_NAV_LAYOUT, tutorialDismissed: false };

function lsKey(username: string | null | undefined) {
  return username ? `${LS_PREFIX}_${username}` : LS_PREFIX;
}

function readLs(username: string | null | undefined): TabPrefsState {
  try {
    const raw = localStorage.getItem(lsKey(username));
    if (!raw) return EMPTY;
    const value = JSON.parse(raw) as Partial<TabPrefsState>;
    return {
      hidden: Array.isArray(value.hidden) ? value.hidden as TabId[] : [],
      tabLabels: value.tabLabels && typeof value.tabLabels === 'object' ? value.tabLabels : {},
      groupLabels: value.groupLabels && typeof value.groupLabels === 'object' ? value.groupLabels : {},
      layout: Array.isArray(value.layout) && value.layout.length ? value.layout : DEFAULT_NAV_LAYOUT,
      tutorialDismissed: value.tutorialDismissed === true,
    };
  } catch { return EMPTY; }
}

function writeLs(username: string | null | undefined, prefs: TabPrefsState) {
  try { localStorage.setItem(lsKey(username), JSON.stringify(prefs)); } catch { /* ignore */ }
}

export function useTabPrefs() {
  const { ready, authed, username } = useAuthState();
  const [prefs, setPrefs] = useState<TabPrefsState>(EMPTY);
  const loadedFor = useRef<string | null>(null);

  useEffect(() => {
    if (!ready) return;
    let cancelled = false;
    const key = authed ? `cloud:${username}` : 'local';
    if (loadedFor.current === key) return;
    loadedFor.current = key;
    setPrefs(readLs(username));
    if (authed) {
      api.userPrefs.get().then(response => {
        if (cancelled) return;
        const next: TabPrefsState = {
          hidden: (response.hidden_tabs ?? []) as TabId[],
          tabLabels: (response.tab_labels ?? {}) as Partial<Record<TabId, string>>,
          groupLabels: (response.group_labels ?? {}) as Partial<Record<TabSectionId, string>>,
          layout: response.nav_layout?.length ? response.nav_layout as NavGroup[] : DEFAULT_NAV_LAYOUT,
          tutorialDismissed: response.nav_tutorial_dismissed === true,
        };
        setPrefs(next);
        writeLs(username, next);
      }).catch(() => { /* keep local mirror */ });
    }
    return () => { cancelled = true; };
  }, [ready, authed, username]);

  const save = useCallback(async (next: TabPrefsState) => {
    if (authed) {
      const response = await api.userPrefs.save(next.hidden, next.tabLabels, next.groupLabels, next.layout, next.tutorialDismissed);
      next = {
        hidden: (response.hidden_tabs ?? []) as TabId[],
        tabLabels: (response.tab_labels ?? {}) as Partial<Record<TabId, string>>,
        groupLabels: (response.group_labels ?? {}) as Partial<Record<TabSectionId, string>>,
        layout: response.nav_layout?.length ? response.nav_layout as NavGroup[] : DEFAULT_NAV_LAYOUT,
        tutorialDismissed: response.nav_tutorial_dismissed === true,
      };
    }
    setPrefs(next);
    writeLs(username, next);
  }, [authed, username]);

  const reset = useCallback(() => save({ ...EMPTY, tutorialDismissed: prefs.tutorialDismissed }), [save, prefs.tutorialDismissed]);
  const dismissTutorial = useCallback(async () => {
    if (authed) await api.userPrefs.save(prefs.hidden, prefs.tabLabels, prefs.groupLabels, prefs.layout, true);
    const next = { ...prefs, tutorialDismissed: true };
    setPrefs(next);
    writeLs(username, next);
  }, [authed, username, prefs]);
  return { ...prefs, save, reset, dismissTutorial };
}
