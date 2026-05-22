import type { Role } from '../../types/api';

const ROLE_LABELS: Record<Role, string> = {
  admin: 'ADMIN',
  pac: 'PAC',
  charlie: 'CHARLIE',
  l1: 'L1',
  l2: 'L2',
};

export function RoleBadge({ role, size = 'sm' }: { role: Role; size?: 'xs' | 'sm' | 'md' }) {
  return (
    <span className={`role-badge role-badge--${role} role-badge--${size}`}>
      {ROLE_LABELS[role]}
    </span>
  );
}
