import type { Role, Team, MeResponse, LoginResponse, UsersListResponse, AppUser, RecentResponse, IrCasesListResponse, IrCaseDetailResponse, IrCasesMutateResponse, LogsResponse, HistoryListResponse, HistoryMutateResponse, UserPrefsResponse, PassiveDnsResponse, CrtShResponse, CveLookupResponse, AttackSearchResponse, UserWebhookResponse, ApiUsageResponse, IpScanAnalyticsResponse, VtQuotaResponse } from '../types/api';
import type { ScanItem } from '../types/vt';
import type { TabId } from './permissions';

/** Error carrying the HTTP status + Retry-After so callers can back off on 429. */
export interface ApiError extends Error {
  status?: number;
  retryAfter?: number; // seconds (from Retry-After header)
  code?: string;
  retryable?: boolean;
  resetAt?: string;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method || 'GET').toUpperCase();
  const isRead = method === 'GET' || method === 'HEAD';
  const requestPath = isRead
    ? `${path}${path.includes('?') ? '&' : '?'}_ts=${Date.now()}`
    : path;
  const res = await fetch(requestPath, {
    credentials: 'include',
    cache: isRead ? 'no-store' : undefined,
    ...init,
    headers: {
      ...(isRead ? { 'Cache-Control': 'no-cache' } : {}),
      ...init?.headers,
    },
  });
  const json = await res.json().catch(() => ({}));
  const body = json as { error?: string | { message?: string; code?: string; retryable?: boolean; resetAt?: string }; message?: string; error_code?: string };
  const e = body.error;
  if (!res.ok) {
    const err: ApiError = new Error(typeof e === 'string' ? e : e?.message || body.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.code = body.error_code;
    if (typeof e === 'object' && e) {
      err.code = e.code;
      err.retryable = e.retryable;
      err.resetAt = e.resetAt;
    }
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
    ipScans: (from: string, to: string) =>
      apiFetch<IpScanAnalyticsResponse>(`/api/admin/ip-scans?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`),
    vtQuota: () => apiFetch<VtQuotaResponse>('/api/admin/vt-quota'),
    usage: (opts: { days?: number; from?: string; to?: string } = { days: 7 }) => {
      const p = new URLSearchParams();
      if (opts.from && opts.to) { p.set('from', opts.from); p.set('to', opts.to); }
      else p.set('days', String(opts.days ?? 7));
      return apiFetch<ApiUsageResponse>(`/api/admin/usage?${p}`);
    },
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
    save: (hidden_tabs: TabId[], tab_labels: Partial<Record<TabId, string>>, group_labels: Partial<Record<string, string>>, nav_layout: Array<{ id: string; label: string; tabs: TabId[] }>, nav_tutorial_dismissed: boolean) =>
      apiFetch<UserPrefsResponse>('/api/user-prefs', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hidden_tabs, tab_labels, group_labels, nav_layout, nav_tutorial_dismissed }),
      }),
  },

  userWebhook: {
    get: () => apiFetch<UserWebhookResponse>('/api/user-webhook'),
    save: (webhook_url: string, enabled: boolean, min_confidence: number) =>
      apiFetch<UserWebhookResponse>('/api/user-webhook', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ webhook_url, enabled, min_confidence }),
      }),
  },

  ipCache: {
    recent: (limit = 50, from?: string, to?: string) => {
      const p = new URLSearchParams({ limit: String(limit) });
      if (from && to) { p.set('from', from); p.set('to', to); }
      return apiFetch<RecentResponse>(`/api/ip-cache/recent?${p}`);
    },
    byId: (id: string) => apiFetch<Record<string, unknown>>(`/api/ip-cache/by-id?id=${encodeURIComponent(id)}`),
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

  teamFilter: {
    get: (team: Team) => apiFetch<{ success: boolean; team_context: Team; items: Array<{ ip: string; payload: Record<string, unknown>; updated_at: string }> }>('/api/v1/team-filter', { headers: { 'X-Team-Context': team } }),
    post: (team: Team, ips: string[]) => apiFetch<Record<string, unknown>>('/api/v1/team-filter', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Team-Context': team },
      body: JSON.stringify({ items: ips.map(ip => ({ ip })) }),
    }),
    delete: (team: Team, ips: string[]) => apiFetch<{ deletedCount: number }>('/api/v1/team-filter', {
      method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-Team-Context': team },
      body: JSON.stringify({ ips }),
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