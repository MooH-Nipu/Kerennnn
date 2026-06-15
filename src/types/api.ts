import type { ScanItem } from './vt';

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

export interface AuditLogEntry {
  id: string;
  actor_username: string | null;
  action: string;
  target: string | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

export interface LoginAttemptEntry {
  id: string;
  username: string;
  ip: string;
  success: boolean;
  attempted_at: string;
}

export interface LogsResponse {
  ok: boolean;
  audit: AuditLogEntry[];
  logins: LoginAttemptEntry[];
}

export interface ScanHistoryEntry {
  id: string;
  input: string;
  count: number;
  items: ScanItem[];
  created_at: string;
}

export interface HistoryListResponse {
  ok: boolean;
  entries: ScanHistoryEntry[];
}

export interface HistoryMutateResponse {
  ok: boolean;
  entry: ScanHistoryEntry;
}

export interface UserPrefsResponse {
  ok: boolean;
  tab_order: string[];
  hidden_tabs: string[];
}

// ── Analyst tools (Initiative 3) ──

export interface PassiveDnsRecord {
  host: string;
  ip?: string;
}

export interface PassiveDnsResponse {
  ok: boolean;
  ioc: string;
  type: 'ip' | 'domain';
  records: PassiveDnsRecord[];
  note?: string;
}

export interface CrtCert {
  issuer: string;
  not_before: string | null;
  not_after: string | null;
  names: string[];
}

export interface CrtShResponse {
  ok: boolean;
  domain: string;
  total: number;
  certs: CrtCert[];
  subdomains: string[];
}

export interface CveCvss {
  version: string;
  score: number | null;
  severity: string | null;
  vector: string | null;
}

export interface CveResult {
  id: string;
  description: string;
  cvss: CveCvss | null;
  published: string | null;
  lastModified: string | null;
  references: string[];
}

export interface CveLookupResponse {
  ok: boolean;
  query: string;
  total: number;
  results: CveResult[];
}

export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  detection: string;
  isSubtechnique: boolean;
  url: string;
}

export interface AttackSearchResponse {
  ok: boolean;
  query: string;
  total: number;
  results: AttackTechnique[];
}

// ── Per-user alert webhook (Settings tab) ──

export interface UserWebhookResponse {
  ok: boolean;
  webhook_url: string;
  enabled: boolean;
  min_confidence: number;
}

// ── Admin API usage analytics ──

export interface UsageByUser {
  username: string;
  total: number;
  ok: number;
  rate_limited: number;
  error: number;
}

export interface UsageRecentRow {
  username: string | null;
  service: string;
  ioc_type: string | null;
  outcome: string;
  api_key: string | null;
  created_at: string;
}

export interface ApiUsageResponse {
  ok: boolean;
  rangeDays?: number;
  from?: string;
  to?: string;
  bucket?: string;
  total: number;
  capped: boolean;
  byUser: UsageByUser[];
  byOutcome: Array<{ outcome: string; total: number }>;
  byDay: Array<{ day: string } & Record<string, number>>;
  recent: UsageRecentRow[];
}
