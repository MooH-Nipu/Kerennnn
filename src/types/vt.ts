export type IocType = 'ip' | 'domain' | 'hash' | null;

export type VtVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout?: number;
}

export interface VtMeta {
  cache: {
    seenBefore: boolean;
    stableId: string | null;
  };
  type: IocType;
  ioc: string;
}

export interface VtIpAttributes {
  country?: string;
  as_owner?: string;
  asn?: number;
  last_analysis_stats?: VtStats;
  last_analysis_results?: Record<string, { category: string; result: string }>;
  reputation?: number;
  network?: string;
  continent?: string;
  regional_internet_registry?: string;
}

export interface VtDomainAttributes {
  registrar?: string;
  creation_date?: number;
  last_dns_records?: Array<{ type: string; value: string }>;
  last_analysis_stats?: VtStats;
  last_analysis_results?: Record<string, { category: string; result: string }>;
  reputation?: number;
  categories?: Record<string, string>;
}

export interface VtHashAttributes {
  meaningful_name?: string;
  type_description?: string;
  size?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  last_analysis_stats?: VtStats;
  last_analysis_results?: Record<string, { category: string; result: string }>;
  tags?: string[];
  names?: string[];
}

export interface VtResult {
  ioc: string;
  type: IocType;
  verdict: VtVerdict;
  stats: VtStats | null;
  attributes: VtIpAttributes | VtDomainAttributes | VtHashAttributes | null;
  _meta: VtMeta;
  error?: string;
}

export interface CorrelationSource {
  source: string;
  verdict?: string;
  detail?: string;
  weight: number;
  score?: number;
  meta?: Record<string, string | number>;
  skipped?: boolean;
  error?: string;
  link?: string;
}

export interface CorrelationResult {
  confidence: number;
  verdict: string;
  sources: CorrelationSource[];
}

export interface ScanItem {
  id: string;
  ioc: string;
  type: IocType;
  result: VtResult | null;
  correlation: CorrelationResult | null;
  correlationLoading: boolean;
  error: string | null;
  pending: boolean;
}
