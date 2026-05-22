import { useAuthState } from '../../context/AuthContext';
import { canViewTab } from '../../lib/permissions';
import type { TabId } from '../../lib/permissions';

interface Props {
  tab: TabId;
  children: React.ReactNode;
}

export function PermissionGuard({ tab, children }: Props) {
  const { role } = useAuthState();

  if (!role || !canViewTab(role, tab)) {
    return (
      <div className="perm-guard-blocked">
        <div className="perm-guard-icon">🔒</div>
        <h3>Akses Ditolak</h3>
        <p>Tab ini tidak tersedia untuk role <strong>{role ?? 'unknown'}</strong>.</p>
      </div>
    );
  }

  return <>{children}</>;
}
