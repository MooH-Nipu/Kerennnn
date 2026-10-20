'use strict';
const { TIPlugin } = require('./_base');
const { getTrustFactor, kp } = require('./_helpers');
const { httpGet } = require('../_http');

// ── AlienVault OTX (weight 0.15, all types) ──────────────────────────────

class OTXPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'AlienVault OTX';
    this.supportedTypes = ['ip', 'domain', 'hash'];
  }

  isAvailable() {
    return !!process.env.OTX_API_KEY;
  }

  async check(ioc, type) {
    const apiKey = process.env.OTX_API_KEY;
    if (!apiKey) return { source: 'AlienVault OTX', skipped: true, reason: 'No API key' };
    const typeMap = { ip: 'IPv4', domain: 'domain', hash: 'file' };
    const otxType = typeMap[type];
    if (!otxType) return { source: 'AlienVault OTX', skipped: true, reason: `Unsupported type: ${type}` };
    try {
      const { status, data } = await httpGet(
        `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`,
        { 'X-OTX-API-KEY': apiKey, Accept: 'application/json' }
      );
      if (status !== 200) return { source: 'AlienVault OTX', error: `OTX: HTTP ${status}` };
      const pulseCount = data.pulse_info?.count || 0;
      const families = data.pulse_info?.related?.malware_families || [];
      const pulses = data.pulse_info?.pulses || [];
      const recentPulse = pulses.some(p => {
        const ts = p.modified || p.created;
        if (!ts) return false;
        const days = (Date.now() - new Date(ts).getTime()) / 86400000;
        return Number.isFinite(days) && days <= 30;
      });
      const verdict =
        (pulseCount >= 5 || (families.length > 0 && recentPulse)) ? 'malicious' :
        pulseCount >= 1 ? 'suspicious' : 'clean';
      return {
        source: 'AlienVault OTX',
        verdict,
        score: Math.min(pulseCount * 10 + (recentPulse ? 10 : 0) + (families.length > 0 ? 10 : 0), 100),
        keyPrefix: kp(apiKey),
        weight: 0.15 * getTrustFactor('TRUST_OTX'),
        meta: {
          'Pulse Count': pulseCount,
          'Recent Pulse (<30d)': recentPulse ? 'yes' : 'no',
          Reputation: data.reputation ?? '—',
          'Type Tags': (data.type_tags || []).slice(0, 3).join(', ') || '—',
          'Malware Families': families.slice(0, 2).join(', ') || '—',
        },
        link: `https://otx.alienvault.com/indicator/${otxType}/${ioc}`,
      };
    } catch (e) {
      return { source: 'AlienVault OTX', error: `Cannot access OTX: ${e.message}` };
    }
  }
}

module.exports = { OTXPlugin };
