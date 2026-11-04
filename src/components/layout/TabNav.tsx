import { useEffect, type ReactNode } from 'react';
import type { Role, Team } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { TAB_ACCESS } from '../../lib/permissions';
import { DEFAULT_NAV_LAYOUT, type NavGroup, type TabSectionId } from '../../hooks/useTabPrefs';

export interface TabDef {
  id: TabId;
  label: string;
  icon: ReactNode;
}

export interface TabSectionDef {
  id: TabSectionId;
  label: string;
  tabs: TabId[];
}

export const TAB_SECTIONS: TabSectionDef[] = DEFAULT_NAV_LAYOUT;

const Icon = ({ children }: { children: ReactNode }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>
);

export const ALL_TABS: TabDef[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <Icon><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></Icon> },
  { id: 'formatter', label: 'Formatter', icon: <Icon><path d="M15 12H3M17 18H3M21 6H3"/></Icon> },
  { id: 'merger', label: 'Merger', icon: <Icon><path d="m8 6 4-4 4 4M12 2v10.3a4 4 0 0 1-1.172 2.872L4 22M20 22l-5-5"/></Icon> },
  { id: 'ioc-scan', label: 'IoC Scan', icon: <Icon><circle cx="12" cy="12" r="3"/><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/></Icon> },
  { id: 'history', label: 'History', icon: <Icon><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5M12 7v5l4 2"/></Icon> },
  { id: 'pac-filter', label: 'Team Filter', icon: <Icon><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></Icon> },
  { id: 'daily-eod', label: 'Daily EOD', icon: <Icon><rect width="18" height="18" x="3" y="4" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></Icon> },
  { id: 'admin-users', label: 'Users', icon: <Icon><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></Icon> },
  { id: 'admin-logs', label: 'Logs', icon: <Icon><path d="M15 12h-5M15 8h-5M19 17V5a2 2 0 0 0-2-2H4"/></Icon> },
  { id: 'ir-manager', label: 'IR Manager', icon: <Icon><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7"/></Icon> },
  { id: 'json', label: 'Log Formatter', icon: <Icon><path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1"/></Icon> },
  { id: 'cve', label: 'CVE Lookup', icon: <Icon><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></Icon> },
  { id: 'attack', label: 'ATT&CK', icon: <Icon><circle cx="12" cy="12" r="10"/><path d="M22 12h-4M6 12H2M12 6V2M12 22v-4"/></Icon> },
  { id: 'settings', label: 'Settings', icon: '⚙' },
  { id: 'admin-usage', label: 'API Usage', icon: <Icon><path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/></Icon> },
];

export function isTabVisible(tab: TabDef, role: Role, allowedTeams: Team[] = []): boolean {
  if (tab.id === 'pac-filter') return allowedTeams.length > 0;
  const allowed = TAB_ACCESS[tab.id];
  return allowed === null || (allowed as Role[]).includes(role);
}

export function allowedTabs(role: Role, hidden: TabId[] = [], activeTab?: TabId, allowedTeams: Team[] = []): TabDef[] {
  const hiddenSet = new Set(hidden);
  return ALL_TABS.filter(tab =>
    isTabVisible(tab, role, allowedTeams)
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
  allowedTeams?: Team[];
}

export function TabNav({ role, activeTab, setActiveTab, hidden = [], tabLabels = {}, groupLabels = {}, layout = DEFAULT_NAV_LAYOUT, pacFilterCount, allowedTeams = [] }: Props) {
  const tabs = allowedTabs(role, hidden, activeTab, allowedTeams);
  const tabsById = new Map(tabs.map(tab => [tab.id, tab]));
  const tabsInSection = (section: NavGroup) => section.tabs.map(id => tabsById.get(id)).filter((tab): tab is TabDef => Boolean(tab));
  const navigationTabs = layout.flatMap(tabsInSection);

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
        const sectionTabs = tabsInSection(section);
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

export function getRestoredTab(role: Role, hidden: TabId[] = [], allowedTeams: Team[] = []): TabId {
  try {
    const stored = localStorage.getItem(getTabMemoryKey(role));
    const saved = (stored === 'syslog' ? 'json' : stored) as TabId | null;
    if (saved && !hidden.includes(saved) && ALL_TABS.some(tab => tab.id === saved && isTabVisible(tab, role, allowedTeams))) return saved;
  } catch { /* ignore */ }
  const preferred = role === 'admin' || role === 'l2' ? 'dashboard' : 'ioc-scan';
  if (!hidden.includes(preferred)) return preferred;
  return allowedTabs(role, hidden, undefined, allowedTeams)[0]?.id ?? 'settings';
}
