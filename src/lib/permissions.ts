import type { Role } from '../types/api';

export const ROLES = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'] as const;

export type TabId =
  | 'dashboard'
  | 'formatter'
  | 'json'
  | 'merger'
  | 'ioc-scan'
  | 'history'
  | 'pac-filter'
  | 'daily-eod'
  | 'admin-users'
  | 'admin-logs'
  | 'ir-manager'
  | 'cve'
  | 'attack'
  | 'settings'
  | 'admin-usage';

// Admin-equivalent roles. L2 is treated as a second admin tier.
export const ADMIN_ROLES: Role[] = ['admin', 'l2'];
export const LEAD_ROLES: Role[] = ['admin', 'soc_lead', 'l2'];
export const TEAM_FILTER_ROLES: Role[] = ['admin', 'soc_lead', 'pac', 'charlie', 'l2'];
const ANALYST_ROLES: Role[] = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];
const ADVANCED_ROLES: Role[] = ['admin', 'soc_lead', 'pac', 'charlie', 'l2'];

// null = any authenticated role; Role[] = specific allowlist
export const TAB_ACCESS: Record<TabId, Role[] | null> = {
  'dashboard':   ADMIN_ROLES,
  'formatter':   ADVANCED_ROLES,
  'json':        ADVANCED_ROLES,
  'merger':      ADVANCED_ROLES,
  'ioc-scan':    ANALYST_ROLES,
  'history':     ANALYST_ROLES,
  'pac-filter':  TEAM_FILTER_ROLES,
  'daily-eod':   ADVANCED_ROLES,
  'admin-users': ADMIN_ROLES,
  'admin-logs':  LEAD_ROLES,
  'ir-manager':  ANALYST_ROLES,
  'cve':         ADVANCED_ROLES,
  'attack':      ADVANCED_ROLES,
  'settings':    ANALYST_ROLES,
  'admin-usage': ADMIN_ROLES,
};

export function canViewTab(role: Role, tab: TabId): boolean {
  const allowed = TAB_ACCESS[tab];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}

export type Action =
  | 'manage:users'
  | 'write:pac-filter'
  | 'read:pac-filter'
  | 'export:pdf'
  | 'export:csv';

export const ACTION_ACCESS: Record<Action, Role[] | null> = {
  'manage:users':     ADMIN_ROLES,
  'write:pac-filter': TEAM_FILTER_ROLES,
  'read:pac-filter':  TEAM_FILTER_ROLES,
  'export:pdf':       null,
  'export:csv':       null,
};

export function canPerform(role: Role, action: Action): boolean {
  const allowed = ACTION_ACCESS[action];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}
