'use strict';

function cacheTtlHours(verdict) {
  if (verdict === 'malicious') return 24;
  if (verdict === 'suspicious') return 6;
  return 1;
}

function isFreshCacheRow(row, now = Date.now()) {
  const observedAt = Date.parse(row?.last_scanned_at || row?.first_scanned_at || '');
  if (!Number.isFinite(observedAt)) return false;
  return now - observedAt < cacheTtlHours(row?.vt_verdict) * 3_600_000;
}

module.exports = { cacheTtlHours, isFreshCacheRow };
