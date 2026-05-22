import { useState } from 'react';

interface UiPrefs {
  compact: boolean;
  sidebar: boolean;
}

const KEY = 'socToolboxUiPrefs';

function loadPrefs(): UiPrefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { compact: false, sidebar: false, ...JSON.parse(raw) };
  } catch { /* ignore */ }
  return { compact: false, sidebar: false };
}

function savePrefs(prefs: UiPrefs) {
  localStorage.setItem(KEY, JSON.stringify(prefs));
}

export function useUiPrefs() {
  const [prefs, setPrefs] = useState<UiPrefs>(loadPrefs);

  function update(patch: Partial<UiPrefs>) {
    setPrefs(prev => {
      const next = { ...prev, ...patch };
      savePrefs(next);
      return next;
    });
  }

  return {
    compact: prefs.compact,
    sidebar: prefs.sidebar,
    toggleCompact: () => update({ compact: !prefs.compact }),
    toggleSidebar: () => update({ sidebar: !prefs.sidebar }),
  };
}
