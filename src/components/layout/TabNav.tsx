import { useEffect } from 'react';
import type { Role } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { TAB_ACCESS } from '../../lib/permissions';

interface TabDef {
  id: TabId;
  label: string;
  shortLabel: string;
  icon: string;
  shortcut: number;
}

const ALL_TABS: TabDef[] = [
  { id: 'formatter',   label: 'Formatter',  shortLabel: 'Fmt',    icon: '≋',  shortcut: 1 },
  { id: 'merger',      label: 'Merger',     shortLabel: 'Merge',  icon: '⇄',  shortcut: 2 },
  { id: 'ioc-scan',    label: 'IoC Scan',   shortLabel: 'Scan',   icon: '◎',  shortcut: 3 },
  { id: 'history',     label: 'Riwayat',    shortLabel: 'Log',    icon: '≡',  shortcut: 4 },
  { id: 'pac-filter',  label: 'PAC Filter', shortLabel: 'PAC',    icon: '⬡',  shortcut: 5 },
  { id: 'daily-eod',   label: 'Daily EOD',  shortLabel: 'EOD',    icon: '▨',  shortcut: 6 },
  { id: 'admin-users', label: 'Users',      shortLabel: 'Users',  icon: '⊕',  shortcut: 7 },
];

function isTabVisible(tab: TabDef, role: Role): boolean {
  const allowed = TAB_ACCESS[tab.id];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}

function getTabMemoryKey(role: Role) {
  return `socToolboxActiveTab_${role}`;
}

interface Props {
  role: Role;
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
  sidebar?: boolean;
  pacFilterCount?: number;
}

export function TabNav({ role, activeTab, setActiveTab, sidebar, pacFilterCount }: Props) {
  const visibleTabs = ALL_TABS.filter(t => isTabVisible(t, role));

  // Persist tab memory per role
  function handleTabClick(id: TabId) {
    setActiveTab(id);
    localStorage.setItem(getTabMemoryKey(role), id);
  }

  // Keyboard shortcuts Alt+1..8
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey) return;
      const num = parseInt(e.key, 10);
      if (isNaN(num) || num < 1) return;
      const tab = visibleTabs[num - 1];
      if (tab) {
        e.preventDefault();
        handleTabClick(tab.id);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visibleTabs]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <nav className={`tab-nav ${sidebar ? 'tab-nav--sidebar' : 'tab-nav--top'}`} aria-label="Navigasi tab">
      {visibleTabs.map(tab => {
        const isActive = activeTab === tab.id;
        const showBadge = tab.id === 'pac-filter' && typeof pacFilterCount === 'number' && pacFilterCount > 0;

        return (
          <button
            key={tab.id}
            className={`tab-btn ${isActive ? 'tab-btn--active' : ''}`}
            onClick={() => handleTabClick(tab.id)}
            title={`${tab.label} (Alt+${tab.shortcut})`}
            aria-current={isActive ? 'page' : undefined}
          >
            <span className="tab-btn__icon" aria-hidden="true">{tab.icon}</span>
            <span className="tab-btn__label">{sidebar ? tab.label : tab.shortLabel}</span>
            <span className="tab-btn__full-label">{tab.label}</span>
            {showBadge && (
              <span className="tab-btn__badge">{pacFilterCount}</span>
            )}
            <span className="tab-btn__shortcut" aria-hidden="true">Alt+{tab.shortcut}</span>
          </button>
        );
      })}
    </nav>
  );
}

export function getRestoredTab(role: Role): TabId {
  try {
    const saved = localStorage.getItem(getTabMemoryKey(role)) as TabId | null;
    if (saved && ALL_TABS.find(t => t.id === saved && isTabVisible(t, role))) {
      return saved;
    }
  } catch { /* ignore */ }
  return 'formatter';
}
