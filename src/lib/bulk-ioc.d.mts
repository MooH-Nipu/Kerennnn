export const MAX_BULK_IOCS: number;
export const MAX_BULK_INPUT_CHARS: number;
export const MAX_BULK_LINES: number;
export const MAX_SELECTED_IOCS: number;
export const MAX_SELECTED_DOMAINS: number;
export type BulkIocType = 'ip' | 'domain' | 'url' | 'hash' | null;
export interface BulkIocRow {
  id: string;
  original: string;
  normalized: string;
  type: BulkIocType;
  valid: boolean;
  duplicate: boolean;
  invalidReason: string;
  selected: boolean;
}
export function parseBulkIocs(raw: string, format?: 'text' | 'csv' | 'json'): BulkIocRow[];
