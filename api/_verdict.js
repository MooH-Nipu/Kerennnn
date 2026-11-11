'use strict';

/**
 * Confidence → operational label. Thresholds mirror confLabel() in
 * src/lib/ioc.ts; duplicated on purpose (server is CommonJS, UI is TS).
 */
function labelFromConfidence(score) {
  if (score === null || score === undefined || score === '') return 'UNKNOWN';
  const n = Number(score);
  if (!Number.isFinite(n)) return 'UNKNOWN';
  if (n >= 70) return 'HIGH RISK';
  if (n >= 40) return 'MEDIUM RISK';
  if (n >= 15) return 'LOW RISK';
  return 'LIKELY CLEAN';
}

/** VirusTotal engine counts → verdict. Mirrors calcVerdict() in src/lib/ioc.ts. */
function calcVtVerdict(malicious, suspicious, total) {
  const mal = Number(malicious) || 0;
  const sus = Number(suspicious) || 0;
  const sum = Number(total) || 0;
  if (!sum) return 'UNKNOWN';
  if (mal > 3) return 'MALICIOUS';
  if (mal > 0 || sus > 3) return 'SUSPICIOUS';
  return 'CLEAN';
}

/** Pulls the VT engine block out of the /api/vt response body. */
function vtStats(vtBody) {
  const attrs = (vtBody && vtBody.data && vtBody.data.attributes) || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious = Number(stats.malicious) || 0;
  const suspicious = Number(stats.suspicious) || 0;
  const undetected = Number(stats.undetected) || 0;
  const harmless = Number(stats.harmless) || 0;
  const total = Object.values(stats).reduce((sum, value) => sum + (Number(value) || 0), 0);
  return {
    malicious, suspicious, undetected, harmless, total,
    reputation: typeof attrs.reputation === 'number' ? attrs.reputation : null,
    country: typeof attrs.country === 'string' ? attrs.country : null,
    asn: typeof attrs.asn === 'number' ? attrs.asn : null,
    asOwner: typeof attrs.as_owner === 'string' ? attrs.as_owner : null,
    verdict: calcVtVerdict(malicious, suspicious, total),
  };
}

module.exports = { labelFromConfidence, calcVtVerdict, vtStats };
