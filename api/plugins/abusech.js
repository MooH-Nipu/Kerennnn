'use strict';
const { TIPlugin } = require('./_base');
const { getTrustFactor, kp } = require('./_helpers');
const { httpPost } = require('../_http');

// ── Abuse.ch / URLhaus (weight 0.20, IP + domain) ────────────────────────

class AbuseChPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'Abuse.ch';
    this.supportedTypes = ['ip', 'domain'];
  }

  isAvailable() {
    return !!(process.env.ABUSECH_API_KEY || process.env.URLHAUS_API_KEY);
  }

  async check(ioc) {
    const apiKey = process.env.ABUSECH_API_KEY || process.env.URLHAUS_API_KEY;
    if (!apiKey) return { source: 'Abuse.ch', skipped: true, reason: 'No API key' };
    try {
      const postBody = `host=${encodeURIComponent(ioc)}`;
      const { status, data } = await httpPost(`https://urlhaus-api.abuse.ch/v1/host/`, postBody, {
        'Auth-Key': apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Charlie-kerennnn/1.0',
      });
      if (status !== 200) {
        const msg = data?.errors?.[0]?.detail || data?.error || data?.message || `HTTP ${status}`;
        return { source: 'Abuse.ch', error: `URLhaus: ${msg}` };
      }
      if (data?.query_status === 'no_results') {
        return {
          source: 'Abuse.ch',
          verdict: 'clean',
          score: 0,
          keyPrefix: kp(apiKey),
          weight: 0.20 * getTrustFactor('TRUST_ABUSECH'),
          meta: { 'URL Count': 0, 'Online URLs': 0, 'First Seen': '—' },
          link: `https://urlhaus.abuse.ch/host/${encodeURIComponent(ioc)}/`,
        };
      }
      const urls = Array.isArray(data?.urls) ? data.urls : [];
      const urlCount = data?.url_count !== undefined ? Number(data.url_count) : urls.length;
      const onlineUrls = urls.filter(u => u?.url_status === 'online').length;
      const verdict = onlineUrls > 0 ? 'malicious' : urlCount > 0 ? 'suspicious' : 'clean';
      return {
        source: 'Abuse.ch',
        verdict,
        score: verdict === 'malicious' ? 80 : verdict === 'suspicious' ? 40 : 0,
        keyPrefix: kp(apiKey),
        weight: 0.20 * getTrustFactor('TRUST_ABUSECH'),
        meta: {
          'URL Count': urlCount || 0,
          'Online URLs': onlineUrls,
          'First Seen': data?.firstseen || '—',
        },
        link: data?.urlhaus_reference || `https://urlhaus.abuse.ch/host/${encodeURIComponent(ioc)}/`,
      };
    } catch (e) {
      return { source: 'Abuse.ch', error: `Cannot access Abuse.ch (URLhaus): ${e.message}` };
    }
  }
}

module.exports = { AbuseChPlugin };
