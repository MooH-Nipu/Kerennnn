export const MAX_SYSLOG_CHARS: number;
export const MAX_SYSLOG_LINES: number;
export const MAX_SYSLOG_RECORD_CHARS: number;
export interface SyslogRecord {
  line: number;
  raw: string;
  valid: boolean;
  format: string | null;
  error?: string;
  fields?: { name: string; value: string }[];
  [key: string]: unknown;
}
export function parseSyslogRecord(raw: string, line?: number): SyslogRecord;
export function parseSyslogInput(input: string): SyslogRecord[];
export function syslogReadable(records: SyslogRecord[]): string;
