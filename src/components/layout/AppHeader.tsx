import { useState, FormEvent } from 'react';
import type { Role } from '../../types/api';
import { useAuthActions } from '../../context/AuthContext';
import { RoleBadge } from '../shared/RoleBadge';

interface Props {
  username: string;
  role: Role;
  compact: boolean;
  sidebar: boolean;
  onToggleCompact: () => void;
  onToggleSidebar: () => void;
  onQuickScan: (ioc: string) => void;
}

export function AppHeader({ username, role, compact, sidebar, onToggleCompact, onToggleSidebar, onQuickScan }: Props) {
  const { logout } = useAuthActions();
  const [scanInput, setScanInput] = useState('');

  function handleQuickScan(e: FormEvent) {
    e.preventDefault();
    const val = scanInput.trim();
    if (val) {
      onQuickScan(val);
      setScanInput('');
    }
  }

  return (
    <header className={`app-header ${compact ? 'app-header--compact' : ''}`}>
      <div className="app-header__brand">
        <span className="app-header__logo" aria-hidden="true">◈</span>
        <span className="app-header__title">Charlie <em>kerennnn</em></span>
      </div>

      <form className="quick-scan-form" onSubmit={handleQuickScan} aria-label="Quick scan">
        <input
          type="text"
          className="quick-scan-input"
          placeholder="IP / domain / hash…"
          value={scanInput}
          onChange={e => setScanInput(e.target.value)}
          aria-label="IOC for quick scan"
        />
        <button type="submit" className="quick-scan-btn" disabled={!scanInput.trim()} aria-label="Scan">
          ◎
        </button>
      </form>

      <div className="app-header__actions">
        <button
          className={`icon-btn ${sidebar ? 'icon-btn--active' : ''}`}
          onClick={onToggleSidebar}
          title={sidebar ? 'Layout top-nav' : 'Layout sidebar'}
          aria-label="Toggle sidebar"
        >
          {sidebar ? '⊟' : '⊞'}
        </button>
        <button
          className={`icon-btn ${compact ? 'icon-btn--active' : ''}`}
          onClick={onToggleCompact}
          title={compact ? 'Mode spacious' : 'Mode compact'}
          aria-label="Toggle compact"
        >
          {compact ? '⊕' : '⊖'}
        </button>

        <div className="header-user">
          <span className="header-user__monogram" aria-hidden="true">
            {username.slice(0, 2).toUpperCase()}
          </span>
          <span className="header-user__name">{username}</span>
          <RoleBadge role={role} size="xs" />
        </div>

        <button className="icon-btn" onClick={() => logout()} title="Logout" aria-label="Logout">
          ⏏
        </button>
      </div>
    </header>
  );
}
