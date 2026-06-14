import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider, useAuthState } from './context/AuthContext';
import { AppShell } from './components/layout/AppShell';
import { LoginPage } from './components/layout/LoginPage';
import { Spinner } from './components/shared/Spinner';
import { useUiPrefs } from './hooks/useUiPrefs';
import { useTabPrefs } from './hooks/useTabPrefs';
import { getRestoredTab, orderedAllowedTabs } from './components/layout/TabNav';
import { UpdateToast } from './components/shared/UpdateToast';
import { ShortcutHelp } from './components/shared/ShortcutHelp';
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
import { CveTab } from './pages/CveTab';
import { AttackTab } from './pages/AttackTab';
import { SettingsTab } from './pages/SettingsTab';
import { AdminUsageTab } from './pages/AdminUsageTab';
import { ResultPage } from './pages/ResultPage';

function AppInner() {
  const { ready, authed, role, username } = useAuthState();
  const { compact, sidebar, toggleCompact, toggleSidebar } = useUiPrefs();
  const { order: tabOrder, save: saveTabPrefs } = useTabPrefs();
  const [activeTab, setActiveTab] = useState<TabId>('formatter');
  const [pendingIoc, setPendingIoc] = useState('');
  const [pacFilterCount, setPacFilterCount] = useState<number | undefined>(undefined);
  // Lazy-mount: track which tabs have been visited so their state survives tab switches.
  const [mountedTabs, setMountedTabs] = useState<Set<TabId>>(() => new Set(['formatter']));
  const [showShortcuts, setShowShortcuts] = useState(false);

  // Keyboard shortcut: ? toggles help overlay
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        // Don't trigger when focused on an input/textarea
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        e.preventDefault();
        setShowShortcuts(s => !s);
      }
      if (e.key === 'Escape' && showShortcuts) {
        setShowShortcuts(false);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [showShortcuts]);

  // Restore last tab for the user's role after login
  useEffect(() => {
    if (authed && role) {
      setActiveTab(getRestoredTab(role));
    }
  }, [authed, role]);

  // Add the active tab to the mounted set on first visit (keep-alive pattern).
  useEffect(() => {
    setMountedTabs(prev => {
      if (prev.has(activeTab)) return prev;
      const next = new Set(prev);
      next.add(activeTab);
      return next;
    });
  }, [activeTab]);

  // If the active tab is no longer allowed for the role, fall back to the first
  // available tab so the user is never staring at an empty selection.
  useEffect(() => {
    if (!authed || !role) return;
    const tabs = orderedAllowedTabs(role, tabOrder);
    if (tabs.length > 0 && !tabs.some(t => t.id === activeTab)) {
      setActiveTab(tabs[0].id);
    }
  }, [authed, role, tabOrder, activeTab]);

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

  function tabElement(id: TabId) {
    switch (id) {
      case 'formatter':   return <FormatterTab />;
      case 'json':        return <JsonTab />;
      case 'merger':      return <MergerTab />;
      case 'ioc-scan':    return <IocScanTab pendingIoc={pendingIoc} onIocConsumed={() => setPendingIoc('')} />;
      case 'history':     return <HistoryTab onReScan={handleReScan} onGoToScan={() => setActiveTab('ioc-scan')} />;
      case 'pac-filter':  return <PacFilterTab onCountChange={setPacFilterCount} />;
      case 'daily-eod':   return <DailyEodTab />;
      case 'admin-users': return <AdminUsersTab />;
      case 'admin-logs':  return <AdminLogsTab />;
      case 'ir-manager':  return <IrManagerTab />;
      case 'cve':         return <CveTab />;
      case 'attack':      return <AttackTab />;
      case 'settings':    return <SettingsTab compact={compact} sidebar={sidebar} onToggleCompact={toggleCompact} onToggleSidebar={toggleSidebar} />;
      case 'admin-usage': return <AdminUsageTab />;
      default:            return <FormatterTab />;
    }
  }

  function renderAllTabs() {
    return Array.from(mountedTabs).map(id => (
      <div key={id} style={{ display: activeTab === id ? 'contents' : 'none' }}>
        {tabElement(id)}
      </div>
    ));
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
        onReorderTabs={(o) => saveTabPrefs(o, [])}
      >
        {renderAllTabs()}
      </AppShell>

      <UpdateToast />
      {showShortcuts && <ShortcutHelp onClose={() => setShowShortcuts(false)} />}
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
