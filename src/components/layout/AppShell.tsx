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
  role, username, activeTab, setActiveTab, pacFilterCount,
  hiddenTabs, tabLabels, groupLabels, layout, showSettingsFeature, allowedTeams, children,
}: Props) {
  return (
    <div className="app-shell app-shell--sidebar">
      <AppHeader
        username={username}
        role={role}
        settingsActive={activeTab === 'settings'}
        showSettingsFeature={showSettingsFeature}
        onOpenSettings={() => setActiveTab('settings')}
      />
      <div className="app-shell__body">
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
        <main className="app-shell__content" id="main-content">{children}</main>
      </div>
    </div>
  );
}
