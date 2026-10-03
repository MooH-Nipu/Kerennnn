import type { Role } from '../../types/api';
import { useEffect, useState } from 'react';
import { useAuthActions } from '../../context/AuthContext';
import { RoleBadge } from '../shared/RoleBadge';

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
    <header className="app-header">
      <div className="app-header__brand">
        <span className="app-header__title">Charlie <em>kerennnn</em></span>
        <span className="app-header__subtitle">SOC Toolbox</span>
      </div>
      <div className="app-header__actions">

        <button
          type="button"
          className="theme-toggle"
          onClick={() => setTheme(current => current === 'dark' ? 'light' : 'dark')}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          <span aria-hidden="true">{theme === 'dark' ? '☼' : '☾'}</span>
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
            <span aria-hidden="true">⚙</span>
          </button>
        </div>
        <div className="header-user">
          <span className="header-user__monogram" aria-hidden="true">{username.slice(0, 2).toUpperCase()}</span>
          <span className="header-user__name">{username}</span>
          <RoleBadge role={role} size="xs" />
        </div>
        <button type="button" className="logout-btn" onClick={() => logout()} title="Logout" aria-label="Logout">
          <span aria-hidden="true">↪</span>
          <span className="logout-btn__label">Logout</span>
        </button>
      </div>
    </header>
  );
}
