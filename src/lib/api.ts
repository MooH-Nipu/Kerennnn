import type { Role, MeResponse, LoginResponse, UsersListResponse, AppUser, RecentResponse, IrCasesListResponse, IrCaseDetailResponse, IrCasesMutateResponse, LogsResponse, HistoryListResponse, HistoryMutateResponse, UserPrefsResponse, PassiveDnsResponse, CrtShResponse, CveLookupResponse, AttackSearchResponse } from '../types/api';
import type { ScanItem } from '../types/vt';
import type { TabId } from './permissions';

/** Error carrying the HTTP status + Retry-After so callers can back off on 429. */
export interface ApiError extends Error {
  status?: number;
  retryAfter?: number; // seconds (from Retry-After header)
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'include', ...init });
  const json = await res.json().catch(() => ({}));
  const e = (json as { error?: string | { message?: string } }).error;
  if (!res.ok) {
    const err: ApiError = new Error(typeof e === 'string' ? e : e?.message || `HTTP ${res.status}`);
    err.status = res.status;
    const ra = Number(res.headers.get('Retry-After'));
    if (Number.isFinite(ra) && ra > 0) err.retryAfter = ra;
    throw err;
  }
  return json as T;
}

function postJson(path: string, body: unknown) {
  return apiFetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// Auth
export const api = {
  auth: {
    me: () => apiFetch<MeResponse>('/api/auth/me'),
    login: (username: string, password: string) =>
      postJson('/api/auth/login', { username, password }) as Promise<LoginResponse>,
    logout: () => postJson('/api/auth/logout', {}),
  },

  admin: {
    listUsers: () => apiFetch<UsersListResponse>('/api/admin/users'),
    createUser: (username: string, password: string, role: Role) =>
      apiFetch<{ ok: boolean; user: AppUser }>('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role }),
      }),
    updateUser: (id: string, updates: { role?: Role; password?: string; username?: string }) =>
      apiFetch<{ ok: boolean; user: AppUser }>('/api/admin/users', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, ...updates }),
      }),
    deleteUser: (id: string) =>
      apiFetch<{ ok: boolean }>('/api/admin/users', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      }),
    logs: () => apiFetch<LogsResponse>('/api/admin/logs'),
  },

  scan: {
    vt: (ioc: string) => apiFetch<Record<string, unknown>>(`/api/vt?ioc=${encodeURIComponent(ioc)}`),
    correlate: (ioc: string) =>
      apiFetch<Record<string, unknown>>(`/api/correlate?ioc=${encodeURIComponent(ioc)}`),
    passiveDns: (ioc: string) =>
      apiFetch<PassiveDnsResponse>(`/api/passive-dns?ioc=${encodeURIComponent(ioc)}`),
    crtsh: (domain: string) =>
      apiFetch<CrtShResponse>(`/api/crt?domain=${encodeURIComponent(domain)}`),
  },

  cve: {
    lookup: (query: string) => {
      const term = query.trim();
      const isId = /^CVE-\d{4}-\d{4,}$/i.test(term);
      const param = isId ? `id=${encodeURIComponent(term)}` : `q=${encodeURIComponent(term)}`;
      return apiFetch<CveLookupResponse>(`/api/cve?${param}`);
    },
  },

  attack: {
    search: (q: string) => apiFetch<AttackSearchResponse>(`/api/attack?q=${encodeURIComponent(q)}`),
  },

  history: {
    list: (limit = 50) =>
      apiFetch<HistoryListResponse>(`/api/scan-history?limit=${limit}`),
    add: (input: string, count: number, items: ScanItem[]) =>
      apiFetch<HistoryMutateResponse>('/api/scan-history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input, count, items }),
      }),
    remove: (id: string) =>
      apiFetch<{ ok: boolean }>('/api/scan-history', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      }),
    clear: () =>
      apiFetch<{ ok: boolean }>('/api/scan-history', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clear: true }),
      }),
  },

  userPrefs: {
    get: () => apiFetch<UserPrefsResponse>('/api/user-prefs'),
    save: (tab_order: TabId[], hidden_tabs: TabId[]) =>
      apiFetch<UserPrefsResponse>('/api/user-prefs', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tab_order, hidden_tabs }),
      }),
  },

  ipCache: {
    recent: (limit = 50) => apiFetch<RecentResponse>(`/api/ip-cache/recent?limit=${limit}`),
    byId: (id: string) => apiFetch<Record<string, unknown>>(`/api/ip-cache/by-id?id=${encodeURIComponent(id)}`),
    saveCorrelation: (ioc: string, correlation: unknown) =>
      apiFetch<{ ok: boolean }>('/api/ip-cache/correlation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ioc, correlation }),
      }),
  },

  irCases: {
    list: (q = '', offset = 0) =>
      apiFetch<IrCasesListResponse>(`/api/ir-cases?q=${encodeURIComponent(q)}&offset=${offset}`),
    detail: (id: string) =>
      apiFetch<IrCaseDetailResponse>(`/api/ir-cases/detail?id=${encodeURIComponent(id)}`),
    create: (title: string, description: string) =>
      apiFetch<IrCasesMutateResponse>('/api/ir-cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, description }),
      }),
    bulkCreate: (rows: Array<{ title: string; description: string }>) =>
      apiFetch<IrCasesMutateResponse>('/api/ir-cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rows),
      }),
    update: (id: string, title: string, description: string) =>
      apiFetch<IrCasesMutateResponse>('/api/ir-cases', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, title, description }),
      }),
    delete: (id: string) =>
      apiFetch<{ ok: boolean }>('/api/ir-cases', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      }),
  },

  mergerDb: {
    get: (password?: string) =>
      apiFetch<Record<string, unknown>>('/api/scan-merger', {
        headers: password ? { 'X-Merger-Password': password } : {},
      }),
    post: (ips: string[], password?: string) =>
      apiFetch<Record<string, unknown>>('/api/scan-merger', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(password ? { 'X-Merger-Password': password } : {}),
        },
        body: JSON.stringify({ items: ips.map(ip => ({ ip })) }),
      }),
    delete: (ips: string[], password?: string) =>
      apiFetch<Record<string, unknown>>('/api/scan-merger', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          ...(password ? { 'X-Merger-Password': password } : {}),
        },
        body: JSON.stringify({ ips }),
      }),
  },
};
