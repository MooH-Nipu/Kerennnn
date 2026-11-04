import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { Role, Team } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import type { NavGroup, TabSectionId } from '../../hooks/useTabPrefs';
import { AppHeader } from './AppHeader';
import { TabNav } from './TabNav';

interface Props {
  role: Role;
  username: string;
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
  onScanIoc: (ioc: string) => void;
  pacFilterCount?: number;
  hiddenTabs: TabId[];
  tabLabels: Partial<Record<TabId, string>>;
  groupLabels: Partial<Record<TabSectionId, string>>;
  layout: NavGroup[];
  showSettingsFeature: boolean;
  allowedTeams: Team[];
  children: React.ReactNode;
}

export function AppShell({
  role, username, activeTab, setActiveTab, onScanIoc, pacFilterCount,
  hiddenTabs, tabLabels, groupLabels, layout, showSettingsFeature, allowedTeams, children,
}: Props) {
  const [query, setQuery] = useState('');
  const field = useRef<HTMLInputElement>(null);

  // Ctrl/Cmd+K focuses the command field from anywhere.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        field.current?.focus();
        field.current?.select();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  function submit(e: FormEvent) {
    e.preventDefault();
    const ioc = query.trim();
    if (!ioc) return;
    onScanIoc(ioc);
    setQuery('');
    field.current?.blur();
  }

  return (
    <div className="app-shell app-shell--sidebar">
      <div className="app-shell__body">
        <aside className="sidebar">
          <div className="sidebar__brand">
            <span className="sidebar__title">Charlie <em>kerennnn</em></span>
            <span className="sidebar__sub">SOC Toolbox</span>
          </div>
          <form className="sidebar__search" onSubmit={submit}>
            <input
              ref={field}
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Paste an IOC to scan"
              aria-label="Paste an IOC to scan"
              autoComplete="off"
              spellCheck={false}
            />
            <kbd aria-hidden="true">Ctrl K</kbd>
          </form>
          <TabNav
            role={role}
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            hidden={hiddenTabs}
            tabLabels={tabLabels}
            groupLabels={groupLabels}
            layout={layout}
            pacFilterCount={pacFilterCount}
            allowedTeams={allowedTeams}
          />
          <AppHeader
            username={username}
            role={role}
            settingsActive={activeTab === 'settings'}
            showSettingsFeature={showSettingsFeature}
            onOpenSettings={() => setActiveTab('settings')}
          />
        </aside>
        <main className="app-shell__content" id="main-content">{children}</main>
      </div>
    </div>
  );
}
