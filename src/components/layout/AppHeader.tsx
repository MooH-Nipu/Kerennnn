import type { Role } from '../../types/api';
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
  return (
    <header className="app-header">
      <div className="app-header__brand">
        <span className="app-header__title">Charlie <em>kerennnn</em></span>
        <span className="app-header__subtitle">SOC Toolbox</span>
      </div>
      <div className="app-header__actions">

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
        <button type="button" className="logout-btn" onClick={() => logout()} title="Sign out" aria-label="Sign out">
          <span aria-hidden="true">↪</span>
          Logout
        </button>
      </div>
    </header>
  );
}
