import type { Role } from '../../types/api';
import { useEffect, useState } from 'react';
import { useAuthActions } from '../../context/AuthContext';
import { RoleBadge } from '../shared/RoleBadge';

const Ico = ({ children }: { children: React.ReactNode }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{children}</svg>
);

interface Props {
  username: string;
  role: Role;
  settingsActive: boolean;
  showSettingsFeature: boolean;
  onOpenSettings: () => void;
}

export function AppHeader({ username, role, settingsActive, showSettingsFeature, onOpenSettings }: Props) {
  const { logout } = useAuthActions();
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      const saved = localStorage.getItem('kerennnn-theme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch { /* ignore unavailable storage */ }
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('kerennnn-theme', theme); } catch { /* ignore unavailable storage */ }
  }, [theme]);

  return (
    <div className="user-menu">
      <div className="user-menu__who">
        <span className="header-user__monogram" aria-hidden="true">{username.slice(0, 2).toUpperCase()}</span>
        <span className="user-menu__name">{username}</span>
        <RoleBadge role={role} size="xs" />
      </div>
      <div className="user-menu__actions">
        <button
          type="button"
          className="theme-toggle"
          onClick={() => setTheme(current => current === 'dark' ? 'light' : 'dark')}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark'
            ? <Ico><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" /></Ico>
            : <Ico><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" /></Ico>}
          <span className="theme-toggle__label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </button>
        <div className="settings-feature-anchor">
          {showSettingsFeature && !settingsActive && (
            <button type="button" className="settings-feature-bubble" onClick={onOpenSettings}>
              <span className="settings-feature-bubble__badge">New</span>
              <strong>Customize your navigation</strong>
              <span>Move, rename, and group sidebar tabs.</span>
            </button>
          )}
          <button
            className={`settings-btn ${settingsActive ? 'settings-btn--active' : ''}`}
            onClick={onOpenSettings}
            title="Settings"
            aria-label="Settings"
            aria-current={settingsActive ? 'page' : undefined}
          >
            <Ico><path d="M20 7h-9M14 17H5" /><circle cx="17" cy="17" r="3" /><circle cx="7" cy="7" r="3" /></Ico>
            <span>Settings</span>
          </button>
        </div>
        <button type="button" className="logout-btn" onClick={() => logout()} title="Logout" aria-label="Logout">
          <Ico><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></Ico>
          <span className="logout-btn__label">Logout</span>
        </button>
      </div>
    </div>
  );
}
