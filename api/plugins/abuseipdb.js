'use strict';
const { TIPlugin } = require('./_base');
const { getTrustFactor, kp } = require('./_helpers');
const { httpGet } = require('../_http');
const { getAbuseIPDBKeys } = require('../_abuseipdbkeys');

// ── AbuseIPDB (weight 0.20, IP only) ─────────────────────────────────────

class AbuseIPDBPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'AbuseIPDB';
    this.supportedTypes = ['ip'];
  }

  isAvailable() {
    return getAbuseIPDBKeys().length > 0;
  }

  async check(ip) {
    const keys = getAbuseIPDBKeys();
    if (!keys.length) return { source: 'AbuseIPDB', skipped: true, reason: 'No API key' };

    let lastError = null;
    let rateLimitedCount = 0;
    for (const key of keys) {
      try {
        const { status, data } = await httpGet(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
          { Key: key, Accept: 'application/json' }
        );
        if (status === 429) { rateLimitedCount++; continue; }
        if (status !== 200)
          return { source: 'AbuseIPDB', error: `AbuseIPDB: ${data?.errors?.[0]?.detail || `HTTP ${status}`}` };
        const d = data.data;
        const score = d.abuseConfidenceScore || 0;
        const reports = d.totalReports || 0;
        const reportBoost = reports >= 25 ? 20 : reports >= 10 ? 10 : reports >= 3 ? 5 : 0;
        const adjustedScore = Math.min(100, score + reportBoost);
        const verdict = adjustedScore >= 50 ? 'malicious' : adjustedScore >= 20 ? 'suspicious' : 'clean';
        return {
          source: 'AbuseIPDB',
          verdict,
          score,
          keyPrefix: kp(key),
          weight: 0.20 * getTrustFactor('TRUST_ABUSEIPDB'),
          meta: {
            'Abuse Score': score + '%',
            'Total Reports': reports,
            'Distinct Reporters': d.numDistinctUsers ?? '—',
            'Last Reported': d.lastReportedAt ? d.lastReportedAt.slice(0, 10) : '—',
            ISP: d.isp || '—',
            'Usage Type': d.usageType || '—',
            Country: d.countryCode || '—',
          },
          link: `https://www.abuseipdb.com/check/${ip}`,
        };
      } catch (e) {
        lastError = e;
      }
    }
    if (rateLimitedCount === keys.length)
      return { source: 'AbuseIPDB', error: 'All keys quota-exhausted (429). Try again tomorrow.' };
    return { source: 'AbuseIPDB', error: `Cannot access AbuseIPDB: ${lastError?.message || 'Unknown error'}` };
  }
}

module.exports = { AbuseIPDBPlugin };
