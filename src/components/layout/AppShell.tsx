import type { Role } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { AppHeader } from './AppHeader';
import { TabNav } from './TabNav';

interface Props {
  role: Role;
  username: string;
  activeTab: TabId;
  setActiveTab: (tab: TabId) => void;
  compact: boolean;
  sidebar: boolean;
  onToggleCompact: () => void;
  onToggleSidebar: () => void;
  onQuickScan: (ioc: string) => void;
  pacFilterCount?: number;
  tabOrder: TabId[];
  hiddenTabs: TabId[];
  onCustomizeTabs: () => void;
  children: React.ReactNode;
}

export function AppShell({
  role, username, activeTab, setActiveTab,
  compact, sidebar, onToggleCompact, onToggleSidebar, onQuickScan,
  pacFilterCount, tabOrder, hiddenTabs, onCustomizeTabs, children,
}: Props) {
  return (
    <div className={`app-shell ${sidebar ? 'app-shell--sidebar' : 'app-shell--topnav'} ${compact ? 'app-shell--compact' : ''}`}>
      <AppHeader
        username={username}
        role={role}
        compact={compact}
        sidebar={sidebar}
        onToggleCompact={onToggleCompact}
        onToggleSidebar={onToggleSidebar}
        onQuickScan={onQuickScan}
      />

      {sidebar ? (
        <div className="app-shell__body">
          <TabNav
            role={role}
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            order={tabOrder}
            hidden={hiddenTabs}
            onCustomize={onCustomizeTabs}
            sidebar
            pacFilterCount={pacFilterCount}
          />
          <main className="app-shell__content" id="main-content">
            {children}
          </main>
        </div>
      ) : (
        <>
          <TabNav
            role={role}
            activeTab={activeTab}
            setActiveTab={setActiveTab}
            order={tabOrder}
            hidden={hiddenTabs}
            onCustomize={onCustomizeTabs}
            pacFilterCount={pacFilterCount}
          />
          <main className="app-shell__content" id="main-content">
            {children}
          </main>
        </>
      )}
    </div>
  );
}
