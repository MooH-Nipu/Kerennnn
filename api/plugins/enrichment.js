'use strict';
const { TIPlugin } = require('./_base');
const { kp } = require('./_helpers');
const { httpGet } = require('../_http');

// ── Enrichment (RDAP + GeoIP, context-only, IP + domain) ─────────────────
// No verdict/weight — contributes to score only via risk factors.

function extractRdapEntityName(entity) {
  try {
    const vcard = entity && entity.vcardArray && entity.vcardArray[1];
    if (Array.isArray(vcard)) {
      const fn = vcard.find(f => Array.isArray(f) && f[0] === 'fn');
      if (fn && fn[3]) return String(fn[3]);
    }
  } catch { /* ignore malformed vcard */ }
  return entity && entity.handle ? String(entity.handle) : null;
}

class EnrichmentPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'Enrichment';
    this.supportedTypes = ['ip', 'domain'];
  }

  isAvailable() {
    return true; // RDAP is keyless; ipinfo optional
  }

  async check(ioc, type) {
    if (type !== 'ip' && type !== 'domain')
      return { source: 'Enrichment', skipped: true, reason: `Unsupported type: ${type}` };
    const meta = {};

    try {
      const path = type === 'ip' ? `ip/${encodeURIComponent(ioc)}` : `domain/${encodeURIComponent(ioc)}`;
      const { status, data } = await httpGet(
        `https://rdap.org/${path}`,
        { Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' },
        { timeout: 7000 }
      );
      if (status === 200 && data && typeof data === 'object') {
        const events = Array.isArray(data.events) ? data.events : [];
        const reg = events.find(e => e && e.eventAction === 'registration');
        if (reg && reg.eventDate) {
          const t = new Date(reg.eventDate).getTime();
          meta.Registered = String(reg.eventDate).slice(0, 10);
          if (Number.isFinite(t)) meta['Age (days)'] = Math.max(0, Math.floor((Date.now() - t) / 86400000));
        }
        const entities = Array.isArray(data.entities) ? data.entities : [];
        const registrar = entities.find(e => Array.isArray(e?.roles) && e.roles.includes('registrar'));
        const regName = registrar && extractRdapEntityName(registrar);
        if (regName) meta.Registrar = regName;
        if (data.country) meta['RIR Country'] = data.country;
        if (data.handle) meta['Handle/CIDR'] = data.handle;
      }
    } catch { /* best-effort */ }

    if (type === 'ip') {
      try {
        const token = process.env.IPINFO_TOKEN;
        if (token) {
          const { status, data } = await httpGet(
            `https://ipinfo.io/${encodeURIComponent(ioc)}/json?token=${encodeURIComponent(token)}`,
            { Accept: 'application/json' }
          );
          if (status === 200 && data && !data.error) {
            if (data.country) meta.Country = data.country;
            if (data.city) meta.City = data.city;
            if (data.org) { meta.Org = data.org; meta.ASN = String(data.org).split(' ')[0]; }
            meta.GeoSource = 'ipinfo.io';
          }
        } else {
          const { status, data } = await httpGet(
            `https://ipwho.is/${encodeURIComponent(ioc)}`,
            { Accept: 'application/json' }
          );
          if (status === 200 && data && data.success !== false) {
            if (data.country_code) meta.Country = data.country_code;
            if (data.city) meta.City = data.city;
            const conn = data.connection || {};
            if (conn.org || conn.isp) meta.Org = conn.org || conn.isp;
            if (conn.asn) meta.ASN = 'AS' + conn.asn;
            meta.GeoSource = 'ipwho.is';
          }
        }
      } catch { /* best-effort */ }
    }

    if (Object.keys(meta).length === 0)
      return { source: 'Enrichment', skipped: true, reason: 'No enrichment data available' };
    return {
      source: 'Enrichment',
      meta,
      // RDAP is keyless; the only key Enrichment can use is the optional ipinfo token.
      keyPrefix: meta.GeoSource === 'ipinfo.io' ? kp(process.env.IPINFO_TOKEN) : null,
      link: type === 'ip' ? `https://rdap.org/ip/${ioc}` : `https://rdap.org/domain/${ioc}`,
    };
  }
}

module.exports = { EnrichmentPlugin };
