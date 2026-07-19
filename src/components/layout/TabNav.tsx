import { useEffect } from 'react';
import type { Role } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { TAB_ACCESS } from '../../lib/permissions';
import { DEFAULT_NAV_LAYOUT, type NavGroup, type TabSectionId } from '../../hooks/useTabPrefs';

export interface TabDef {
  id: TabId;
  label: string;
  icon: string;
}

export interface TabSectionDef {
  id: TabSectionId;
  label: string;
  tabs: TabId[];
}

export const TAB_SECTIONS: TabSectionDef[] = DEFAULT_NAV_LAYOUT;

export const ALL_TABS: TabDef[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '▦' },
  { id: 'formatter', label: 'Formatter', icon: '≋' },
  { id: 'merger', label: 'Merger', icon: '⇄' },
  { id: 'ioc-scan', label: 'IoC Scan', icon: '◎' },
  { id: 'history', label: 'History', icon: '≡' },
  { id: 'pac-filter', label: 'PAC Filter', icon: '⬡' },
  { id: 'daily-eod', label: 'Daily EOD', icon: '▨' },
  { id: 'admin-users', label: 'Users', icon: '⊕' },
  { id: 'admin-logs', label: 'Logs', icon: '🗎' },
  { id: 'ir-manager', label: 'IR Manager', icon: '⚑' },
  { id: 'json', label: 'JSON', icon: '{}' },
  { id: 'cve', label: 'CVE Lookup', icon: '🛡' },
  { id: 'attack', label: 'ATT&CK', icon: '🎯' },
  { id: 'settings', label: 'Settings', icon: '⚙' },
  { id: 'admin-usage', label: 'API Usage', icon: '⌁' },
];

export function isTabVisible(tab: TabDef, role: Role): boolean {
  const allowed = TAB_ACCESS[tab.id];
  return allowed === null || (allowed as Role[]).includes(role);
}

export function allowedTabs(role: Role, hidden: TabId[] = [], activeTab?: TabId): TabDef[] {
  const hiddenSet = new Set(hidden);
  return ALL_TABS.filter(tab =>
    isTabVisible(tab, role)
    && (!hiddenSet.has(tab.id) || tab.id === activeTab || tab.id === 'settings')
  );
}

function getTabMemoryKey(role: Role) {
  return `socToolboxActiveTab_${role}`;
}

interface Props {
  role: Role;
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
  hidden?: TabId[];
  tabLabels?: Partial<Record<TabId, string>>;
  groupLabels?: Partial<Record<TabSectionId, string>>;
  layout?: NavGroup[];
  pacFilterCount?: number;
}

export function TabNav({ role, activeTab, setActiveTab, hidden = [], tabLabels = {}, groupLabels = {}, layout = DEFAULT_NAV_LAYOUT, pacFilterCount }: Props) {
  const tabs = allowedTabs(role, hidden, activeTab);
  const navigationTabs = layout.flatMap(section => tabs.filter(tab => section.tabs.includes(tab.id)));

  function activate(id: TabId) {
    setActiveTab(id);
    localStorage.setItem(getTabMemoryKey(role), id);
  }

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (!event.altKey) return;
      const number = Number.parseInt(event.key, 10);
      if (!Number.isFinite(number) || number < 1 || number > 9) return;
      const tab = navigationTabs[number - 1];
      if (!tab) return;
      event.preventDefault();
      activate(tab.id);
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigationTabs, role]); // eslint-disable-line react-hooks/exhaustive-deps

  function renderTab(tab: TabDef) {
    const index = navigationTabs.findIndex(item => item.id === tab.id);
    const shortcut = index < 9 ? index + 1 : null;
    const label = tabLabels[tab.id] || tab.label;
    const active = activeTab === tab.id;
    const showBadge = tab.id === 'pac-filter' && typeof pacFilterCount === 'number' && pacFilterCount > 0;
    return (
      <button
        key={tab.id}
        className={`tab-btn ${active ? 'tab-btn--active' : ''}`}
        onClick={() => activate(tab.id)}
        title={shortcut ? `${label} (Alt+${shortcut})` : label}
        aria-current={active ? 'page' : undefined}
      >
        <span className="tab-btn__icon" aria-hidden="true">{tab.icon}</span>
        <span className="tab-btn__label">{label}</span>
        <span className="tab-btn__meta" aria-hidden="true">
          {showBadge && <span className="tab-btn__badge">{pacFilterCount}</span>}
          <span className="tab-btn__shortcut">{shortcut ? `Alt+${shortcut}` : ''}</span>
        </span>
      </button>
    );
  }

  return (
    <nav className="tab-nav tab-nav--sidebar" aria-label="Primary navigation">
      {layout.map(section => {
        const sectionTabs = tabs.filter(tab => section.tabs.includes(tab.id));
        if (!sectionTabs.length) return null;
        const label = groupLabels[section.id] || section.label;
        return (
          <div
            className={`tab-nav__section tab-nav__section--${section.id}`}
            key={section.id}
            role="group"
            aria-label={label}
          >
            {section.label && <div className="tab-nav__section-label">{label}</div>}
            {sectionTabs.map(renderTab)}
          </div>
        );
      })}
    </nav>
  );
}

export function getRestoredTab(role: Role, hidden: TabId[] = []): TabId {
  try {
    const saved = localStorage.getItem(getTabMemoryKey(role)) as TabId | null;
    if (saved && !hidden.includes(saved) && ALL_TABS.some(tab => tab.id === saved && isTabVisible(tab, role))) return saved;
  } catch { /* ignore */ }
  const preferred = role === 'admin' || role === 'l2' ? 'dashboard' : 'ioc-scan';
  if (!hidden.includes(preferred)) return preferred;
  return allowedTabs(role, hidden)[0]?.id ?? 'settings';
}
