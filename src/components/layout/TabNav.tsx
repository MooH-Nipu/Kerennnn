import { useEffect, useRef, useState } from 'react';
import type { Role } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { TAB_ACCESS } from '../../lib/permissions';

export interface TabDef {
  id: TabId;
  label: string;
  shortLabel: string;
  icon: string;
}

// Canonical tab list in DEFAULT order. Per-user order is layered on top via the
// `order` prop (see useTabPrefs); users reorder by dragging tabs directly.
const ALL_TABS: TabDef[] = [
  { id: 'formatter',   label: 'Formatter',  shortLabel: 'Fmt',    icon: '≋'  },
  { id: 'merger',      label: 'Merger',     shortLabel: 'Merge',  icon: '⇄'  },
  { id: 'ioc-scan',    label: 'IoC Scan',   shortLabel: 'Scan',   icon: '◎'  },
  { id: 'history',     label: 'History',    shortLabel: 'Log',    icon: '≡'  },
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
// in `order` keep their default ALL_TABS position and sort after ordered ones
// (so newly added tabs always show up).
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

function getTabMemoryKey(role: Role) {
  return `socToolboxActiveTab_${role}`;
}

interface Props {
  role: Role;
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
  order: TabId[];
  onReorder: (order: TabId[]) => void;
  sidebar?: boolean;
  pacFilterCount?: number;
}

export function TabNav({ role, activeTab, setActiveTab, order, onReorder, sidebar, pacFilterCount }: Props) {
  const baseTabs = orderedAllowedTabs(role, order);
  const baseIds = baseTabs.map(t => t.id);
  const defById = new Map(baseTabs.map(t => [t.id, t]));

  // While dragging we render from a transient working order; we only persist
  // (onReorder) once, on drag end — not on every dragover.
  const [dragOrder, setDragOrder] = useState<TabId[] | null>(null);
  const [draggingId, setDraggingId] = useState<TabId | null>(null);
  const dragId = useRef<TabId | null>(null);

  const ids = dragOrder ?? baseIds;
  const tabs = ids.map(id => defById.get(id)).filter(Boolean) as TabDef[];

  function handleTabClick(id: TabId) {
    setActiveTab(id);
    localStorage.setItem(getTabMemoryKey(role), id);
  }

  // Keyboard shortcuts Alt+1..9 — bound to the committed visible order.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.altKey) return;
      const num = parseInt(e.key, 10);
      if (isNaN(num) || num < 1) return;
      const list = orderedAllowedTabs(role, order);
      const tab = list[num - 1];
      if (tab) {
        e.preventDefault();
        setActiveTab(tab.id);
        localStorage.setItem(getTabMemoryKey(role), tab.id);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [role, order]); // eslint-disable-line react-hooks/exhaustive-deps

  function onDragStart(id: TabId) {
    dragId.current = id;
    setDraggingId(id);
    setDragOrder(baseIds);
  }

  function onDragOver(e: React.DragEvent, overId: TabId) {
    e.preventDefault();
    const id = dragId.current;
    if (id == null || id === overId) return;
    setDragOrder(prev => {
      const cur = prev ?? baseIds;
      const from = cur.indexOf(id);
      const to = cur.indexOf(overId);
      if (from < 0 || to < 0 || from === to) return cur;
      const next = [...cur];
      next.splice(from, 1);
      next.splice(to, 0, id);
      return next;
    });
  }

  function onDragEnd() {
    const committed = dragOrder;
    dragId.current = null;
    setDraggingId(null);
    setDragOrder(null);
    if (committed) onReorder(committed);
  }

  return (
    <nav className={`tab-nav ${sidebar ? 'tab-nav--sidebar' : 'tab-nav--top'}`} aria-label="Tab navigation">
      {tabs.map((tab, idx) => {
        const isActive = activeTab === tab.id;
        const showBadge = tab.id === 'pac-filter' && typeof pacFilterCount === 'number' && pacFilterCount > 0;
        const shortcut = idx < 9 ? idx + 1 : null; // only single-digit Alt+N fire

        return (
          <button
            key={tab.id}
            className={`tab-btn ${isActive ? 'tab-btn--active' : ''} ${draggingId === tab.id ? 'tab-btn--dragging' : ''}`}
            onClick={() => handleTabClick(tab.id)}
            draggable
            onDragStart={() => onDragStart(tab.id)}
            onDragOver={e => onDragOver(e, tab.id)}
            onDragEnd={onDragEnd}
            title={shortcut ? `${tab.label} (Alt+${shortcut}) — drag to reorder` : `${tab.label} — drag to reorder`}
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
