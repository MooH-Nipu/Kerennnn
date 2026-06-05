import { useEffect } from 'react';
import type { Role } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { TAB_ACCESS } from '../../lib/permissions';

export interface TabDef {
  id: TabId;
  label: string;
  shortLabel: string;
  icon: string;
}

// Canonical tab list in DEFAULT order. Per-user order/visibility is layered on
// top via the `order`/`hidden` props (see useTabPrefs + TabCustomizer).
const ALL_TABS: TabDef[] = [
  { id: 'formatter',   label: 'Formatter',  shortLabel: 'Fmt',    icon: '≋'  },
  { id: 'merger',      label: 'Merger',     shortLabel: 'Merge',  icon: '⇄'  },
  { id: 'ioc-scan',    label: 'IoC Scan',   shortLabel: 'Scan',   icon: '◎'  },
  { id: 'history',     label: 'Riwayat',    shortLabel: 'Log',    icon: '≡'  },
  { id: 'pac-filter',  label: 'PAC Filter', shortLabel: 'PAC',    icon: '⬡'  },
  { id: 'daily-eod',   label: 'Daily EOD',  shortLabel: 'EOD',    icon: '▨'  },
  { id: 'admin-users', label: 'Users',      shortLabel: 'Users',  icon: '⊕'  },
  { id: 'admin-logs',  label: 'Logs',       shortLabel: 'Logs',   icon: '🗎'  },
  { id: 'ir-manager',  label: 'IR Manager', shortLabel: 'IR',     icon: '⚑'  },
  { id: 'json',        label: 'JSON',       shortLabel: 'JSON',   icon: '{}' },
];

function isTabVisible(tab: TabDef, role: Role): boolean {
  const allowed = TAB_ACCESS[tab.id];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}

// Role-allowed tabs, reordered by the user's preferred `order`. Ids not present
// in `order` keep their default ALL_TABS position and sort after ordered ones.
export function orderedAllowedTabs(role: Role, order: TabId[]): TabDef[] {
  const allowed = ALL_TABS.filter(t => isTabVisible(t, role));
  const rank = new Map<TabId, number>();
  order.forEach((id, i) => rank.set(id, i));
  return allowed
    .map((t, i) => ({ t, i }))
    .sort((a, b) => {
      const ra = rank.has(a.t.id) ? (rank.get(a.t.id) as number) : Infinity;
      const rb = rank.has(b.t.id) ? (rank.get(b.t.id) as number) : Infinity;
      if (ra !== rb) return ra - rb;
      return a.i - b.i; // stable fallback: default order
    })
    .map(x => x.t);
}

// Tabs actually shown in the nav: ordered, role-allowed, minus hidden ones.
export function visibleOrderedTabs(role: Role, order: TabId[], hidden: TabId[]): TabDef[] {
  const hiddenSet = new Set(hidden);
  return orderedAllowedTabs(role, order).filter(t => !hiddenSet.has(t.id));
}

function getTabMemoryKey(role: Role) {
  return `socToolboxActiveTab_${role}`;
}

interface Props {
  role: Role;
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
  order: TabId[];
  hidden: TabId[];
  onCustomize: () => void;
  sidebar?: boolean;
  pacFilterCount?: number;
}

export function TabNav({ role, activeTab, setActiveTab, order, hidden, onCustomize, sidebar, pacFilterCount }: Props) {
  const visibleTabs = visibleOrderedTabs(role, order, hidden);

  // Persist tab memory per role
  function handleTabClick(id: TabId) {
    setActiveTab(id);
    localStorage.setItem(getTabMemoryKey(role), id);
  }

  // Keyboard shortcuts Alt+1..9 (bound to the user's visible order)
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
      {visibleTabs.map((tab, idx) => {
        const isActive = activeTab === tab.id;
        const showBadge = tab.id === 'pac-filter' && typeof pacFilterCount === 'number' && pacFilterCount > 0;
        const shortcut = idx < 9 ? idx + 1 : null; // only single-digit Alt+N fire

        return (
          <button
            key={tab.id}
            className={`tab-btn ${isActive ? 'tab-btn--active' : ''}`}
            onClick={() => handleTabClick(tab.id)}
            title={shortcut ? `${tab.label} (Alt+${shortcut})` : tab.label}
            aria-current={isActive ? 'page' : undefined}
          >
            <span className="tab-btn__icon" aria-hidden="true">{tab.icon}</span>
            <span className="tab-btn__label">{sidebar ? tab.label : tab.shortLabel}</span>
            <span className="tab-btn__full-label">{tab.label}</span>
            {showBadge && (
              <span className="tab-btn__badge">{pacFilterCount}</span>
            )}
            {shortcut && (
              <span className="tab-btn__shortcut" aria-hidden="true">Alt+{shortcut}</span>
            )}
          </button>
        );
      })}

      <button
        className="tab-btn tab-btn--customize"
        onClick={onCustomize}
        title="Atur tab (urutan & tampil/sembunyi)"
        aria-label="Atur tab"
      >
        <span className="tab-btn__icon" aria-hidden="true">⚙</span>
        <span className="tab-btn__label">{sidebar ? 'Atur Tab' : 'Atur'}</span>
        <span className="tab-btn__full-label">Atur Tab</span>
      </button>
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
