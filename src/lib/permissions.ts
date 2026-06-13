import type { Role } from '../types/api';

export const ROLES = ['admin', 'pac', 'charlie', 'l1', 'l2'] as const;

export type TabId =
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
// Roles allowed to read/write the PAC Filter DB.
export const PAC_ROLES: Role[] = ['admin', 'pac', 'charlie', 'l2'];

// null = any authenticated role; Role[] = specific allowlist
export const TAB_ACCESS: Record<TabId, Role[] | null> = {
  'formatter':   null,
  'json':        null,
  'merger':      null,
  'ioc-scan':    null,
  'history':     null,
  'pac-filter':  PAC_ROLES,
  'daily-eod':   null,
  'admin-users': ADMIN_ROLES,
  'admin-logs':  ADMIN_ROLES,
  'ir-manager':  null,
  'cve':         null,
  'attack':      null,
  'settings':    null,
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
  'write:pac-filter': PAC_ROLES,
  'read:pac-filter':  PAC_ROLES,
  'export:pdf':       null,
  'export:csv':       null,
};

export function canPerform(role: Role, action: Action): boolean {
  const allowed = ACTION_ACCESS[action];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}
