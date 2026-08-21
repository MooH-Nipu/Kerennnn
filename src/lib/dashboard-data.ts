import type { IpScanAnalyticsResponse } from '../types/api';

export function aggregateUserScans(rows: IpScanAnalyticsResponse['byUser']) {
  const sorted = [...rows].sort((a, b) => b.scans - a.scans);
  const top = sorted.slice(0, 6);
  const rest = sorted.slice(6).reduce((total, row) => total + row.scans, 0);
  return rest > 0 ? [...top, { username: 'Other', scans: rest, uniqueIps: null }] : top;
}
