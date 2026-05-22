import type { Role } from '../types/api';

export const ROLES = ['admin', 'pac', 'charlie', 'l1', 'l2'] as const;

export type TabId =
  | 'dashboard'
  | 'formatter'
  | 'merger'
  | 'ioc-scan'
  | 'history'
  | 'pac-filter'
  | 'daily-eod'
  | 'admin-users';

// null = any authenticated role; Role[] = specific allowlist
export const TAB_ACCESS: Record<TabId, Role[] | null> = {
  'dashboard':   null,
  'formatter':   null,
  'merger':      null,
  'ioc-scan':    null,
  'history':     null,
  'pac-filter':  ['pac', 'charlie'],
  'daily-eod':   null,
  'admin-users': ['admin'],
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
  'manage:users':     ['admin'],
  'write:pac-filter': ['pac', 'charlie'],
  'read:pac-filter':  ['pac', 'charlie'],
  'export:pdf':       null,
  'export:csv':       null,
};

export function canPerform(role: Role, action: Action): boolean {
  const allowed = ACTION_ACCESS[action];
  if (allowed === null) return true;
  return (allowed as Role[]).includes(role);
}
