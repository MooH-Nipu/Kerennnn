'use strict';
const { TIPlugin } = require('./_base');
const { getTrustFactor, kp } = require('./_helpers');
const { httpGet } = require('../_http');
const { getVtKeysForRequest, markVtKeyRateLimited, markVtKeyQuotaExceeded, shouldTryNextVtKey, isVtTemporaryRateLimit, isVtQuotaExceeded, isVtBadKey } = require('../_vtkeys');
const { getSupabase } = require('../_supabase');
const { isFreshCacheRow } = require('../_vt-cache-policy');

// ── VirusTotal (weight 0.30, all types) ──────────────────────────────────

// Builds the VirusTotal source result from last_analysis_stats. Shared by the
// live-API path and the cache-reuse path so scoring stays identical.
function buildVtResult(stats, ioc, type, reputation) {
  const s = stats || {};
  const mal = s.malicious || 0;
  const sus = s.suspicious || 0;
  const total = Object.values(s).reduce((a, b) => a + b, 0);
  const ratio = total > 0 ? (mal + sus) / total : 0;
  const score = Math.round(ratio * 100);
  const verdict =
    (mal >= 5 || score >= 10) ? 'malicious' :
    (mal >= 1 || sus >= 3 || score >= 5) ? 'suspicious' :
    total === 0 ? 'unknown' : 'clean';
  const vtUrlMap = {
    hash: `https://www.virustotal.com/gui/file/${ioc}`,
    ip: `https://www.virustotal.com/gui/ip-address/${ioc}`,
    domain: `https://www.virustotal.com/gui/domain/${ioc}`,
  };
  return {
    source: 'VirusTotal',
    verdict,
    score,
    weight: 0.30 * getTrustFactor('TRUST_VT'),
    meta: {
      Malicious: mal,
      Suspicious: sus,
      Undetected: s.undetected || 0,
      'Total Engines': total,
      'Detection %': score + '%',
      Reputation: Number.isFinite(reputation) ? reputation : '—',
    },
    link: vtUrlMap[type],
  };
}

// Reuse the VT scan that /api/vt already performed + cached for this IP, so a
// single IP scan spends ONE VT request total instead of two (vt.js + here).
async function vtFromIpCache(ip) {
  const supabase = getSupabase();
  if (!supabase) return null;
  try {
    const { data: row } = await supabase
      .from('vt_ip_cache')
      .select('vt_payload,vt_verdict,last_scanned_at,first_scanned_at')
      .eq('ip', ip)
      .maybeSingle();
    const stats = row?.vt_payload?.last_analysis_stats;
    if (isFreshCacheRow(row) && stats && Object.keys(stats).length > 0) {
      return buildVtResult(stats, ip, 'ip', row.vt_payload?.reputation);
    }
  } catch {
    // fall through to live API
  }
  return null;
}

class VirusTotalPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'VirusTotal';
    this.supportedTypes = ['ip', 'domain', 'hash'];
  }

  isAvailable() {
    // Always available: IP cache reuse works even without keys.
    return true;
  }

  async check(ioc, type) {
    // For IPs, /api/vt already fetched + cached VT — reuse it, no second API call.
    if (type === 'ip') {
      const cached = await vtFromIpCache(ioc);
      if (cached) return cached;
    }

    const keys = getVtKeysForRequest();
    if (!keys.length) return { source: 'VirusTotal', skipped: true, reason: 'No API key' };

    const urlMap = {
      hash: `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
      ip: `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
      domain: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`,
    };
    const url = urlMap[type];
    if (!url) return { source: 'VirusTotal', skipped: true, reason: `Unsupported type: ${type}` };

    let lastError = null;
    let rateLimitedCount = 0;
    let quotaExceededCount = 0;
    let badKeyCount = 0;
    for (const key of keys) {
      try {
        const { status, data } = await httpGet(url, {
          'x-apikey': key,
          Accept: 'application/json',
          'User-Agent': 'Charlie-kerennnn/1.0',
        });
        if (shouldTryNextVtKey(status, data)) {
          if (isVtQuotaExceeded(status, data)) { quotaExceededCount++; markVtKeyQuotaExceeded(key); }
          else if (isVtTemporaryRateLimit(status, data)) { rateLimitedCount++; markVtKeyRateLimited(key); }
          else if (isVtBadKey(status, data)) badKeyCount++;
          continue;
        }
        if (status !== 200)
          return { source: 'VirusTotal', error: data?.error?.message || `HTTP ${status}` };

        const attributes = data.data?.attributes;
        return { ...buildVtResult(attributes?.last_analysis_stats, ioc, type, attributes?.reputation), keyPrefix: kp(key) };
      } catch (e) {
        lastError = e;
      }
    }
    if (badKeyCount === keys.length)
      return { source: 'VirusTotal', error: 'All configured API keys are invalid or inactive.' };
    if (quotaExceededCount > 0 && quotaExceededCount + badKeyCount === keys.length)
      return { source: 'VirusTotal', error: 'No usable VirusTotal keys remain; quota exhausted and automatic short retry disabled.' };
    if (rateLimitedCount > 0 && rateLimitedCount + quotaExceededCount + badKeyCount === keys.length)
      return { source: 'VirusTotal', error: 'All available VirusTotal keys are temporarily rate-limited.' };
    return { source: 'VirusTotal', error: `Cannot access VirusTotal: ${lastError?.message || 'Unknown error'}` };
  }
}

module.exports = { VirusTotalPlugin, buildVtResult };
