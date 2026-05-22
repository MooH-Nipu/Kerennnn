import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider, useAuthState } from './context/AuthContext';
import { AppShell } from './components/layout/AppShell';
import { LoginPage } from './components/layout/LoginPage';
import { Spinner } from './components/shared/Spinner';
import { useUiPrefs } from './hooks/useUiPrefs';
import { getRestoredTab } from './components/layout/TabNav';
import type { TabId } from './lib/permissions';
import { DashboardTab } from './pages/DashboardTab';
import { FormatterTab } from './pages/FormatterTab';
import { MergerTab } from './pages/MergerTab';
import { IocScanTab } from './pages/IocScanTab';
import { HistoryTab } from './pages/HistoryTab';
import { PacFilterTab } from './pages/PacFilterTab';
import { DailyEodTab } from './pages/DailyEodTab';
import { AdminUsersTab } from './pages/AdminUsersTab';
import { ResultPage } from './pages/ResultPage';

function AppInner() {
  const { ready, authed, role, username } = useAuthState();
  const { compact, sidebar, toggleCompact, toggleSidebar } = useUiPrefs();
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [pendingIoc, setPendingIoc] = useState('');
  const [pacFilterCount, setPacFilterCount] = useState<number | undefined>(undefined);

  // Restore last tab for the user's role after login
  useEffect(() => {
    if (authed && role) {
      setActiveTab(getRestoredTab(role));
    }
  }, [authed, role]);

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
      case 'dashboard':   return <DashboardTab onScanIp={ip => { setPendingIoc(ip); setActiveTab('ioc-scan'); }} />;
      case 'formatter':   return <FormatterTab />;
      case 'merger':      return <MergerTab />;
      case 'ioc-scan':    return <IocScanTab pendingIoc={pendingIoc} onIocConsumed={() => setPendingIoc('')} />;
      case 'history':     return <HistoryTab onReScan={handleReScan} />;
      case 'pac-filter':  return <PacFilterTab onCountChange={setPacFilterCount} />;
      case 'daily-eod':   return <DailyEodTab />;
      case 'admin-users': return <AdminUsersTab />;
      default:            return <DashboardTab />;
    }
  }

  return (
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
    >
      {renderTabContent()}
    </AppShell>
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
