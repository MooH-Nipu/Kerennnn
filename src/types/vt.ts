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
  weight?: number;        // absent on context-only sources (Enrichment, Shodan)
  score?: number;
  meta?: Record<string, string | number>;
  skipped?: boolean;
  error?: string;
  link?: string;
}

export type RiskSeverity = 'high' | 'med' | 'low';

export interface RiskFactor {
  type: string;
  severity: RiskSeverity;
  source: string;
  message: string;
  bonus?: number;
}

export interface CorrelationResult {
  confidence: number;
  verdict?: string;       // not included in correlate.js response; derived client-side via confToVerdict
  sources: CorrelationSource[];
  riskFactors?: RiskFactor[];
  baselineConfidence?: number | null;
  floor?: number;
  bonus?: number;
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
