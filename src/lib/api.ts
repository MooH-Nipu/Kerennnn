import type { Role, MeResponse, LoginResponse, UsersListResponse, AppUser, RecentResponse, IrCasesListResponse, IrCaseDetailResponse, IrCasesMutateResponse } from '../types/api';

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'include', ...init });
  const json = await res.json().catch(() => ({}));
  const e = (json as { error?: string | { message?: string } }).error;
  if (!res.ok) throw new Error(typeof e === 'string' ? e : e?.message || `HTTP ${res.status}`);
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
    updateUser: (id: string, updates: { role?: Role; password?: string }) =>
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
  },

  scan: {
    vt: (ioc: string) => apiFetch<Record<string, unknown>>(`/api/vt?ioc=${encodeURIComponent(ioc)}`),
    correlate: (ioc: string) =>
      apiFetch<Record<string, unknown>>(`/api/correlate?ioc=${encodeURIComponent(ioc)}`),
  },

  ipCache: {
    recent: (limit = 50) => apiFetch<RecentResponse>(`/api/ip-cache/recent?limit=${limit}`),
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
