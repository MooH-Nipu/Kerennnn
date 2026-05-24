export type Role = 'admin' | 'pac' | 'charlie' | 'l1' | 'l2';

export interface MeResponse {
  ok: boolean;
  role: Role;
  username: string;
}

export interface LoginResponse {
  ok: boolean;
  role: Role;
  username: string;
}

export interface AppUser {
  id: string;
  username: string;
  role: Role;
  created_at: string;
  created_by: string | null;
}

export interface UsersListResponse {
  ok: boolean;
  users: AppUser[];
}

export interface RecentIp {
  ip: string;
  id: string;
  vt_verdict: string | null;
  corr_confidence: number | null;
  first_scanned_at: string;
}

export interface RecentResponse {
  ok: boolean;
  ttlDays?: number;
  items: RecentIp[];
}

export interface IrCase {
  id: string;
  title: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  description?: string;
}

export interface IrCasesListResponse {
  ok: boolean;
  cases: IrCase[];
  total: number;
}

export interface IrCaseDetailResponse {
  ok: boolean;
  case: IrCase & { description: string };
}

export interface IrCasesMutateResponse {
  ok: boolean;
  cases?: IrCase[];
  case?: IrCase;
}
