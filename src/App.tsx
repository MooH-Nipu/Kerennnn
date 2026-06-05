import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider, useAuthState } from './context/AuthContext';
import { AppShell } from './components/layout/AppShell';
import { LoginPage } from './components/layout/LoginPage';
import { Spinner } from './components/shared/Spinner';
import { useUiPrefs } from './hooks/useUiPrefs';
import { useTabPrefs } from './hooks/useTabPrefs';
import { getRestoredTab, visibleOrderedTabs } from './components/layout/TabNav';
import { TabCustomizer } from './components/layout/TabCustomizer';
import type { TabId } from './lib/permissions';
import { FormatterTab } from './pages/FormatterTab';
import { JsonTab } from './pages/JsonTab';
import { MergerTab } from './pages/MergerTab';
import { IocScanTab } from './pages/IocScanTab';
import { HistoryTab } from './pages/HistoryTab';
import { PacFilterTab } from './pages/PacFilterTab';
import { DailyEodTab } from './pages/DailyEodTab';
import { AdminUsersTab } from './pages/AdminUsersTab';
import { AdminLogsTab } from './pages/AdminLogsTab';
import { IrManagerTab } from './pages/IrManagerTab';
import { ResultPage } from './pages/ResultPage';

function AppInner() {
  const { ready, authed, role, username } = useAuthState();
  const { compact, sidebar, toggleCompact, toggleSidebar } = useUiPrefs();
  const { order: tabOrder, hidden: hiddenTabs, save: saveTabPrefs, reset: resetTabPrefs } = useTabPrefs();
  const [activeTab, setActiveTab] = useState<TabId>('formatter');
  const [pendingIoc, setPendingIoc] = useState('');
  const [pacFilterCount, setPacFilterCount] = useState<number | undefined>(undefined);
  const [customizerOpen, setCustomizerOpen] = useState(false);

  // Restore last tab for the user's role after login
  useEffect(() => {
    if (authed && role) {
      setActiveTab(getRestoredTab(role));
    }
  }, [authed, role]);

  // If the active tab is hidden (or no longer allowed), fall back to the first
  // visible tab so the user is never staring at an empty/hidden selection.
  useEffect(() => {
    if (!authed || !role) return;
    const visible = visibleOrderedTabs(role, tabOrder, hiddenTabs);
    if (visible.length > 0 && !visible.some(t => t.id === activeTab)) {
      setActiveTab(visible[0].id);
    }
  }, [authed, role, tabOrder, hiddenTabs, activeTab]);

  function handleQuickScan(ioc: string) {
    setPendingIoc(ioc);
    setActiveTab('ioc-scan');
  }

  function handleReScan(ioc: string) {
    setPendingIoc(ioc);
    setActiveTab('ioc-scan');
  }

  if (!ready) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: 'var(--text-muted)' }}>
        <Spinner size={32} />
      </div>
    );
  }

  if (!authed || !role || !username) {
    return <LoginPage />;
  }

  function renderTabContent() {
    switch (activeTab) {
      case 'formatter':   return <FormatterTab />;
      case 'json':        return <JsonTab />;
      case 'merger':      return <MergerTab />;
      case 'ioc-scan':    return <IocScanTab pendingIoc={pendingIoc} onIocConsumed={() => setPendingIoc('')} />;
      case 'history':     return <HistoryTab onReScan={handleReScan} />;
      case 'pac-filter':  return <PacFilterTab onCountChange={setPacFilterCount} />;
      case 'daily-eod':   return <DailyEodTab />;
      case 'admin-users': return <AdminUsersTab />;
      case 'admin-logs':  return <AdminLogsTab />;
      case 'ir-manager':  return <IrManagerTab />;
      default:            return <FormatterTab />;
    }
  }

  return (
    <>
      <AppShell
        role={role}
        username={username}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        compact={compact}
        sidebar={sidebar}
        onToggleCompact={toggleCompact}
        onToggleSidebar={toggleSidebar}
        onQuickScan={handleQuickScan}
        pacFilterCount={pacFilterCount}
        tabOrder={tabOrder}
        hiddenTabs={hiddenTabs}
        onCustomizeTabs={() => setCustomizerOpen(true)}
      >
        {renderTabContent()}
      </AppShell>

      <TabCustomizer
        open={customizerOpen}
        role={role}
        order={tabOrder}
        hidden={hiddenTabs}
        onClose={() => setCustomizerOpen(false)}
        onSave={(o, h) => { saveTabPrefs(o, h); setCustomizerOpen(false); }}
        onReset={() => { resetTabPrefs(); setCustomizerOpen(false); }}
      />
    </>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/result/:id" element={<ResultPage />} />
          <Route path="/*" element={<AppInner />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
