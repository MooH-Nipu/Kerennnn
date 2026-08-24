import type { Role, Team } from '../types/api';

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
const ANALYST_ROLES: Role[] = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];


// null = any authenticated role; Role[] = specific allowlist
export const TAB_ACCESS: Record<TabId, Role[] | null> = {
  'dashboard':   ADMIN_ROLES,
  'formatter':   null,
  'json':        null,
  'merger':      null,
  'ioc-scan':    ANALYST_ROLES,
  'history':     ANALYST_ROLES,
  'pac-filter':  [],
  'daily-eod':   null,
  'admin-users': ADMIN_ROLES,
  'admin-logs':  LEAD_ROLES,
  'ir-manager':  ANALYST_ROLES,
  'cve':         null,
  'attack':      null,
  'settings':    ANALYST_ROLES,
  'admin-usage': ADMIN_ROLES,
};

export function canViewTab(role: Role, tab: TabId, allowedTeams: Team[] = []): boolean {
  if (tab === 'pac-filter') return allowedTeams.length > 0;
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
  'write:pac-filter': [],
  'read:pac-filter':  [],
  'export:pdf':       null,
  'export:csv':       null,
};

export function canPerform(role: Role, action: Action, allowedTeams: Team[] = []): boolean {
  if (action === 'read:pac-filter' || action === 'write:pac-filter') return allowedTeams.length > 0;
  const allowed = ACTION_ACCESS[action];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}
