import { lazy, Suspense, useState, useEffect, useRef } from 'react';
import { AuthProvider, useAuthState } from './context/AuthContext';
import { AppShell } from './components/layout/AppShell';
import { LoginPage } from './components/layout/LoginPage';
import { Spinner } from './components/shared/Spinner';
import { L1_NAV_LAYOUT, useTabPrefs } from './hooks/useTabPrefs';
import { allowedTabs, getRestoredTab } from './components/layout/TabNav';
import { UpdateToast } from './components/shared/UpdateToast';
import { ShortcutHelp } from './components/shared/ShortcutHelp';
import type { TabId } from './lib/permissions';

const DashboardTab = lazy(() => import('./pages/DashboardTab').then(m => ({ default: m.DashboardTab })));
const FormatterTab = lazy(() => import('./pages/FormatterTab').then(m => ({ default: m.FormatterTab })));
const JsonTab = lazy(() => import('./pages/JsonTab').then(m => ({ default: m.JsonTab })));
const MergerTab = lazy(() => import('./pages/MergerTab').then(m => ({ default: m.MergerTab })));
const IocScanTab = lazy(() => import('./pages/IocScanTab').then(m => ({ default: m.IocScanTab })));
const HistoryTab = lazy(() => import('./pages/HistoryTab').then(m => ({ default: m.HistoryTab })));
const PacFilterTab = lazy(() => import('./pages/PacFilterTab').then(m => ({ default: m.PacFilterTab })));
const DailyEodTab = lazy(() => import('./pages/DailyEodTab').then(m => ({ default: m.DailyEodTab })));
const AdminUsersTab = lazy(() => import('./pages/AdminUsersTab').then(m => ({ default: m.AdminUsersTab })));
const AdminLogsTab = lazy(() => import('./pages/AdminLogsTab').then(m => ({ default: m.AdminLogsTab })));
const IrManagerTab = lazy(() => import('./pages/IrManagerTab').then(m => ({ default: m.IrManagerTab })));
const CveTab = lazy(() => import('./pages/CveTab').then(m => ({ default: m.CveTab })));
const AttackTab = lazy(() => import('./pages/AttackTab').then(m => ({ default: m.AttackTab })));
const SettingsTab = lazy(() => import('./pages/SettingsTab').then(m => ({ default: m.SettingsTab })));
const AdminUsageTab = lazy(() => import('./pages/AdminUsageTab').then(m => ({ default: m.AdminUsageTab })));
const ResultPage = lazy(() => import('./pages/ResultPage').then(m => ({ default: m.ResultPage })));

function safeDecodePathSegment(value: string) {
  try { return decodeURIComponent(value); } catch { return ''; }
}

function AppInner() {
  const { ready, authed, role, username, activeTeam, allowedTeams } = useAuthState();
  const workspaceIdentity = authed && role && username ? `${username}:${role}:${allowedTeams.join(',')}` : null;
  const workspaceIdentityRef = useRef(workspaceIdentity);
  const tabPrefs = useTabPrefs();
  const { hidden: hiddenTabs, tabLabels, groupLabels, layout } = tabPrefs;
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [pendingIoc, setPendingIoc] = useState('');
  const [pacFilterCount, setPacFilterCount] = useState<number | undefined>(undefined);
  // Lazy-mount: track which tabs have been visited so their state survives tab switches.
  const [mountedTabs, setMountedTabs] = useState<Set<TabId>>(() => new Set(['dashboard']));
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

  // Reset keep-alive state before the next identity may mount old tab children.
  useEffect(() => {
    if (!authed || !role || !username || !workspaceIdentity) {
      workspaceIdentityRef.current = workspaceIdentity;
      return;
    }
    const restored = getRestoredTab(role, hiddenTabs, allowedTeams);
    workspaceIdentityRef.current = workspaceIdentity;
    setActiveTab(restored);
    setMountedTabs(new Set([restored]));
    setPendingIoc('');
    setPacFilterCount(undefined);
    // hiddenTabs is intentionally excluded: later preference changes are handled
    // by the permission fallback below without resetting the current tab.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspaceIdentity]);

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
    const tabs = allowedTabs(role, hiddenTabs, undefined, allowedTeams);
    if (tabs.length > 0 && !tabs.some(t => t.id === activeTab)) {
      setActiveTab(tabs[0].id);
    }
  }, [authed, role, hiddenTabs, activeTab, allowedTeams]);

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

  if (workspaceIdentityRef.current !== workspaceIdentity) {
    return <div className="app-loading"><Spinner size={32} /></div>;
  }

  function tabElement(id: TabId) {
    switch (id) {
      case 'dashboard':  return <DashboardTab onScanIp={handleQuickScan} />;
      case 'formatter':   return <FormatterTab />;
      case 'json':        return <JsonTab />;
      case 'merger':      return <MergerTab />;
      case 'ioc-scan':    return <IocScanTab pendingIoc={pendingIoc} onIocConsumed={() => setPendingIoc('')} />;
      case 'history':     return <HistoryTab onReScan={handleReScan} onGoToScan={() => setActiveTab('ioc-scan')} />;
      case 'pac-filter':  return activeTeam ? <PacFilterTab key={`${workspaceIdentity}:${activeTeam}`} team={activeTeam} identity={workspaceIdentity!} canManageClients={role === 'admin' || role === 'soc_lead' || role === 'l2'} onCountChange={setPacFilterCount} /> : <div className="empty-state">No team filter access.</div>;
      case 'daily-eod':   return <DailyEodTab />;
      case 'admin-users': return <AdminUsersTab />;
      case 'admin-logs':  return <AdminLogsTab />;
      case 'ir-manager':  return <IrManagerTab />;
      case 'cve':         return <CveTab />;
      case 'attack':      return <AttackTab />;
      case 'settings':    return <SettingsTab role={role as NonNullable<typeof role>} prefs={tabPrefs} />;
      case 'admin-usage': return <AdminUsageTab />;
      default:            return <FormatterTab />;
    }
  }

  function renderAllTabs() {
    const permitted = new Set(allowedTabs(role!, hiddenTabs, activeTab, allowedTeams).map(tab => tab.id));
    return Array.from(mountedTabs).filter(id => permitted.has(id)).map(id => (
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
        pacFilterCount={pacFilterCount}
        hiddenTabs={hiddenTabs}
        tabLabels={tabLabels}
        groupLabels={groupLabels}
        layout={role === 'l1' ? L1_NAV_LAYOUT : layout}
        showSettingsFeature={role !== 'l1' && !tabPrefs.tutorialDismissed}
        allowedTeams={allowedTeams}
      >
        <Suspense fallback={<Spinner size={32} />}>{renderAllTabs()}</Suspense>
      </AppShell>

      <UpdateToast />
      {showShortcuts && <ShortcutHelp onClose={() => setShowShortcuts(false)} />}
    </>
  );
}

export function App() {
  const resultMatch = window.location.pathname.match(/^\/result\/([^/]+)$/);
  return (
    <AuthProvider>
      {resultMatch
        ? <Suspense fallback={<Spinner size={32} />}><ResultPage id={safeDecodePathSegment(resultMatch[1])} /></Suspense>
        : <AppInner />}
    </AuthProvider>
  );
}
