'use strict';
const { extractIOC, detectType } = require('./_ioc');
const { httpGet, httpPost } = require('./_http');
const { getVtKeysForRequest, markVtKeyRateLimited, shouldTryNextVtKey, isVtRateLimited, isVtBadKey } = require('./_vtkeys');
const { getAbuseIPDBKeys } = require('./_abuseipdbkeys');
const { requireAuth } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { logApiUsage } = require('./_usage');

function getTrustFactor(envKey, defaultValue = 1) {
  const raw = process.env[envKey];
  if (raw === undefined || raw === null || raw === '') return defaultValue;
  const n = Number.parseFloat(raw);
  if (!Number.isFinite(n) || n < 0) return defaultValue;
  return n;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Substring match against commonly-abused hosting providers (case-insensitive).
const HIGH_RISK_HOSTERS = [
  'digitalocean', 'ovh', 'vultr', 'choopa', 'linode', 'akamai connected cloud',
  'hetzner', 'm247', 'quadranet', 'frantech', 'buyvm', 'worldstream',
  'nforce', 'cogent', 'leaseweb', 'datacamp', 'psychz', 'constant company',
  'serverius', 'host sailor', 'shock hosting', 'colocrossing', 'incognet',
];

function ispIsHighRiskHoster(isp) {
  if (!isp) return null;
  const lower = String(isp).toLowerCase();
  for (const needle of HIGH_RISK_HOSTERS) {
    if (lower.includes(needle)) return needle;
  }
  return null;
}

// ── Source: VirusTotal (weight 0.30, all types) ───────────────────────────

// Builds the VirusTotal source result from last_analysis_stats. Shared by the
// live-API path and the cache-reuse path so scoring stays identical.
function buildVtResult(stats, ioc, type) {
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
    const cutoffIso = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString();
    const { data: row } = await supabase
      .from('vt_ip_cache')
      .select('vt_payload')
      .eq('ip', ip)
      .gt('first_scanned_at', cutoffIso)
      .maybeSingle();
    const stats = row?.vt_payload?.last_analysis_stats;
    if (stats && Object.keys(stats).length > 0) return buildVtResult(stats, ip, 'ip');
  } catch {
    // fall through to live API
  }
  return null;
}

async function checkVT(ioc, type) {
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
  let badKeyCount = 0;
  for (const key of keys) {
    try {
      const { status, data } = await httpGet(url, {
        'x-apikey': key,
        Accept: 'application/json',
        'User-Agent': 'Charlie-kerennnn/1.0',
      });
      if (shouldTryNextVtKey(status, data)) {
        if (isVtRateLimited(status, data)) { rateLimitedCount++; markVtKeyRateLimited(key); }
        else if (isVtBadKey(status, data)) badKeyCount++;
        continue;
      }
      if (status !== 200)
        return { source: 'VirusTotal', error: data?.error?.message || `HTTP ${status}` };

      return buildVtResult(data.data?.attributes?.last_analysis_stats, ioc, type);
    } catch (e) {
      lastError = e;
    }
  }
  if (badKeyCount === keys.length)
    return { source: 'VirusTotal', error: 'All configured API keys are invalid or inactive.' };
  if (rateLimitedCount === keys.length)
    return { source: 'VirusTotal', error: 'All keys hit VirusTotal rate limits (per-minute or daily quota).' };
  return { source: 'VirusTotal', error: `Cannot access VirusTotal: ${lastError?.message || 'Unknown error'}` };
}

// ── Source: AbuseIPDB (weight 0.20, IP only) ──────────────────────────────
async function checkAbuseIPDB(ip) {
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

// ── Source: Abuse.ch / URLhaus (weight 0.20, IP + domain) ─────────────────
async function checkAbuseCh(ioc) {
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

// ── Source: AlienVault OTX (weight 0.15, all types) ──────────────────────
async function checkOTX(ioc, type) {
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

// ── Source: URLScan.io (weight 0.20, domain only) ─────────────────────────
// Two-step: POST submit → poll GET result. Adds ~10-15s latency for domain IOCs.
// Runs concurrently in Promise.all so it doesn't block other sources.
async function checkURLScan(domain) {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) return { source: 'URLScan.io', skipped: true, reason: 'No API key' };
  try {
    const submitBody = JSON.stringify({ url: `https://${domain}`, visibility: 'unlisted' });
    const { status: submitStatus, data: submitData } = await httpPost(
      'https://urlscan.io/api/v1/scan/',
      submitBody,
      {
        'API-Key': apiKey,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(submitBody),
        Accept: 'application/json',
        'User-Agent': 'Charlie-kerennnn/1.0',
      },
      { timeout: 10000 }
    );
    if (submitStatus !== 200)
      return { source: 'URLScan.io', error: `Submit failed: HTTP ${submitStatus}` };

    const uuid = submitData?.uuid;
    if (!uuid) return { source: 'URLScan.io', error: 'No scan UUID returned' };

    // Scans complete in 5-10s; poll up to 4 times at 3s intervals after initial 5s wait.
    await sleep(5000);
    let result = null;
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        const { status, data } = await httpGet(
          `https://urlscan.io/api/v1/result/${uuid}/`,
          { 'API-Key': apiKey, Accept: 'application/json' },
          { timeout: 5000 }
        );
        if (status === 200) { result = data; break; }
      } catch { /* not ready yet */ }
      if (attempt < 3) await sleep(3000);
    }

    if (!result) return { source: 'URLScan.io', error: 'Scan result not ready (timed out)' };

    const verdicts = result.verdicts?.overall;
    const malicious = verdicts?.malicious ?? false;
    const overallScore = verdicts?.score ?? 0;
    const tags = (verdicts?.tags || []).slice(0, 4);

    const verdict = malicious ? 'malicious' : overallScore > 50 ? 'suspicious' : 'clean';

    return {
      source: 'URLScan.io',
      verdict,
      score: Math.min(100, overallScore),
      weight: 0.20 * getTrustFactor('TRUST_URLSCAN'),
      meta: {
        Title: (result.page?.title || '—').slice(0, 60),
        'Status Code': result.page?.status || '—',
        Tags: tags.join(', ') || '—',
        Screenshot: result.screenshot || '—',
      },
      link: result.result || `https://urlscan.io/result/${uuid}/`,
    };
  } catch (e) {
    return { source: 'URLScan.io', error: `Cannot access URLScan.io: ${e.message}` };
  }
}

// ── Source: Enrichment (RDAP + GeoIP, context-only, IP + domain) ──────────
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

async function checkEnrichment(ioc, type) {
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
    link: type === 'ip' ? `https://rdap.org/ip/${ioc}` : `https://rdap.org/domain/${ioc}`,
  };
}

// ── Risk factor collection ────────────────────────────────────────────────
function collectRiskFactors(results) {
  const factors = [];
  for (const r of results) {
    if (r.skipped || r.error) continue;
    const m = r.meta || {};

    if (r.source === 'VirusTotal') {
      const mal = Number(m.Malicious) || 0;
      if (mal >= 1) {
        factors.push({
          type: 'vt_detection',
          severity: mal >= 5 ? 'high' : 'med',
          source: 'VirusTotal',
          message: `${mal}/${Number(m['Total Engines']) || 0} engines flagged malicious`,
          bonus: mal >= 5 ? 10 : 5,
        });
      }
    }

    if (r.source === 'AbuseIPDB') {
      const reports = Number(m['Total Reports']) || 0;
      if (reports >= 25) {
        factors.push({ type: 'many_reports', severity: 'high', source: 'AbuseIPDB', message: `${reports} abuse reports (90 days)`, bonus: 15 });
      } else if (reports >= 10) {
        factors.push({ type: 'many_reports', severity: 'med', source: 'AbuseIPDB', message: `${reports} abuse reports (90 days)`, bonus: 10 });
      }
      const hoster = ispIsHighRiskHoster(m.ISP);
      if (hoster) {
        factors.push({ type: 'hosting_provider', severity: 'med', source: 'AbuseIPDB', message: `Hosted at ${m.ISP} (commonly abused)`, bonus: 10 });
      }
      const usage = String(m['Usage Type'] || '').toLowerCase();
      if (!hoster && (usage.includes('data center') || usage.includes('hosting') || usage.includes('transit'))) {
        factors.push({ type: 'datacenter_usage', severity: 'low', source: 'AbuseIPDB', message: `Usage type: ${m['Usage Type']}`, bonus: 5 });
      }
    }

    if (r.source === 'AlienVault OTX') {
      const families = String(m['Malware Families'] || '');
      if (families && families !== '—') {
        factors.push({ type: 'malware_family', severity: 'high', source: 'AlienVault OTX', message: `Associated malware family: ${families}`, bonus: 10 });
      }
      if (m['Recent Pulse (<30d)'] === 'yes') {
        factors.push({ type: 'recent_pulse', severity: 'med', source: 'AlienVault OTX', message: 'Active pulse within last 30 days', bonus: 5 });
      }
    }

    if (r.source === 'Abuse.ch') {
      const online = Number(m['Online URLs']) || 0;
      if (online > 0) {
        factors.push({ type: 'urlhaus_online', severity: 'high', source: 'Abuse.ch', message: `${online} active malicious URLs on URLhaus`, bonus: 10 });
      }
    }

    if (r.source === 'URLScan.io') {
      if (r.verdict === 'malicious') {
        factors.push({ type: 'urlscan_malicious', severity: 'high', source: 'URLScan.io', message: 'URLScan.io flagged page as malicious', bonus: 12 });
      }
      if (String(m.Tags || '').toLowerCase().includes('phishing')) {
        factors.push({ type: 'urlscan_phishing', severity: 'high', source: 'URLScan.io', message: 'Phishing page detected by URLScan.io', bonus: 12 });
      }
    }

    if (r.source === 'Enrichment') {
      const age = Number(m['Age (days)']);
      if (Number.isFinite(age)) {
        if (age < 30) {
          factors.push({ type: 'new_registration', severity: 'high', source: 'Enrichment', message: `Newly registered (${age} days ago)`, bonus: 10 });
        } else if (age < 90) {
          factors.push({ type: 'new_registration', severity: 'med', source: 'Enrichment', message: `Recently registered (${age} days ago)`, bonus: 5 });
        }
      }
      const org = m.Org || m.ISP || m.ASN || '';
      if (ispIsHighRiskHoster(org)) {
        factors.push({ type: 'hosting_provider', severity: 'med', source: 'Enrichment', message: `High-risk ASN/org: ${org}`, bonus: 10 });
      }
    }
  }

  // Dedupe by factor type — keep highest-bonus instance to prevent double-counting.
  const byType = new Map();
  for (const f of factors) {
    const prev = byType.get(f.type);
    if (!prev || (f.bonus || 0) > (prev.bonus || 0)) byType.set(f.type, f);
  }
  return [...byType.values()];
}

// ── Weighted confidence + risk floors + factor bonus ──────────────────────
function calcConfidenceWithFloors(results, factors) {
  const verdictScore = { malicious: 1.0, suspicious: 0.5, unknown: 0.2, clean: 0.0 };

  let weightedSum = 0;
  let totalWeight = 0;
  let maliciousWeight = 0;
  let suspiciousWeight = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  for (const r of results) {
    if (r.skipped || r.error || r.verdict === undefined) continue;
    const w = r.weight;
    const vs = verdictScore[r.verdict] ?? 0;
    weightedSum += vs * w;
    totalWeight += w;
    if (r.verdict === 'malicious') { maliciousWeight += w; maliciousCount++; }
    else if (r.verdict === 'suspicious') { suspiciousWeight += w; suspiciousCount++; }
  }
  if (totalWeight === 0) return { baseline: null, floor: 0, bonus: 0, confidence: null };
  const baseline = Math.round((weightedSum / totalWeight) * 100);

  // Trust-weighted floors — dual condition (absolute weight OR ratio of active weight)
  // so sparse configs (e.g. VT-only) still produce the right floor without over-triggering
  // for low-trust-only source combinations.
  const maliciousRatio = maliciousWeight / totalWeight;
  const suspiciousRatio = suspiciousWeight / totalWeight;
  let floor = 0;
  if      (maliciousWeight >= 0.50 || (maliciousRatio >= 0.60 && maliciousCount >= 2))   floor = 70;
  else if (maliciousWeight >= 0.20 || (maliciousRatio >= 0.50 && maliciousCount >= 1))   floor = 40;
  else if (suspiciousWeight >= 0.50 || (suspiciousRatio >= 0.60 && suspiciousCount >= 2)) floor = 40;
  else if (suspiciousWeight >= 0.25 || (suspiciousRatio >= 0.40 && suspiciousCount >= 1)) floor = 25;

  const bonus = Math.min((factors || []).reduce((sum, f) => sum + (f.bonus || 0), 0), 25);
  const confidence = Math.min(100, Math.max(baseline, floor) + bonus);

  return { baseline, floor, bonus, confidence };
}

// ── MALICIOUS alert webhook (fires when confidence ≥ ALERT_THRESHOLD) ───────
// Best-effort Slack/Teams/Discord (payload auto-detected from URL) or generic
// JSON POST. Fire-and-forget — never blocks or fails the scan response.
const ALERT_THRESHOLD = 70;

function buildAlertText(ioc, type, confidence, factors, resultUrl) {
  const top = (factors || []).slice(0, 3).map(f => `• ${f.message}`).join('\n');
  return `🚨 MALICIOUS IOC detected (${confidence}%)\n` +
    `${String(type).toUpperCase()}: ${ioc}` +
    (top ? `\n${top}` : '') +
    (resultUrl ? `\n${resultUrl}` : '');
}

// Look up the cached row id so the alert can deep-link to /result/:id.
async function lookupStableId(ioc, type) {
  const supabase = getSupabase();
  if (!supabase) return null;
  try {
    if (type === 'ip') {
      const { data } = await supabase.from('vt_ip_cache').select('id').eq('ip', ioc).maybeSingle();
      return data?.id || null;
    }
    const { data } = await supabase.from('vt_ioc_cache').select('id').eq('ioc_type', type).eq('ioc', ioc).maybeSingle();
    return data?.id || null;
  } catch {
    return null;
  }
}

async function fireAlertWebhook(url, ioc, type, confidence, factors) {
  let resultUrl = null;
  const base = process.env.APP_BASE_URL;
  if (base) {
    const id = await lookupStableId(ioc, type);
    if (id) resultUrl = `${base.replace(/\/$/, '')}/result/${id}`;
  }
  const text = buildAlertText(ioc, type, confidence, factors, resultUrl);
  const headers = { 'Content-Type': 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' };
  let body;
  if (/hooks\.slack\.com/i.test(url)) body = JSON.stringify({ text });
  else if (/discord(?:app)?\.com\/api\/webhooks/i.test(url)) body = JSON.stringify({ content: text });
  else if (/webhook\.office\.com|office365\.com|outlook\.office/i.test(url)) body = JSON.stringify({ text });
  else body = JSON.stringify({ ioc, type, confidence, riskFactors: (factors || []).slice(0, 5), resultUrl });
  try {
    // httpPost rejects on non-JSON responses (Slack returns "ok", Discord 204) but
    // the POST is sent regardless — we only swallow the parse rejection here.
    await httpPost(url, body, headers, { timeout: 5000 });
  } catch {
    /* best-effort */
  }
}

// Resolve the webhook to fire for this request: the scanning user's own webhook
// (from user_webhooks) takes precedence; otherwise fall back to a global
// ALERT_WEBHOOK_URL env. The per-user min_confidence overrides ALERT_THRESHOLD.
async function maybeFireAlert(req, ioc, type, confidence, factors) {
  let url = null;
  let threshold = ALERT_THRESHOLD;

  const supabase = getSupabase();
  const userId = req && req.auth ? req.auth.userId : null;
  if (supabase && userId) {
    try {
      const { data } = await supabase
        .from('user_webhooks')
        .select('webhook_url, enabled, min_confidence')
        .eq('user_id', userId)
        .maybeSingle();
      if (data && data.enabled && data.webhook_url) {
        url = data.webhook_url;
        if (Number.isFinite(data.min_confidence)) threshold = data.min_confidence;
      }
    } catch {
      /* fall through to env fallback */
    }
  }
  if (!url && process.env.ALERT_WEBHOOK_URL) url = process.env.ALERT_WEBHOOK_URL;
  if (!url || !(confidence >= threshold)) return;
  await fireAlertWebhook(url, ioc, type, confidence, factors);
}

// ── Handler ───────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const { ioc: rawIoc } = req.query;
  if (!rawIoc) return res.status(400).json({ error: 'Missing ?ioc= param.' });

  const ioc = extractIOC(rawIoc);
  const type = detectType(ioc);
  if (!type) return res.status(400).json({ error: `Cannot detect IOC type for: "${ioc}"` });

  // Build check list based on IOC type.
  // MalwareBazaar is keyless — always runs for hash types.
  const checks = [
    checkVT(ioc, type),        // all types
    checkOTX(ioc, type),       // all types
  ];

  if (type === 'ip') {
    checks.push(checkAbuseIPDB(ioc));
  }

  if (type === 'ip' || type === 'domain') {
    checks.push(checkAbuseCh(ioc));
    checks.push(checkEnrichment(ioc, type));
  }

  if (type === 'domain') checks.push(checkURLScan(ioc));

  const results = await Promise.all(checks);

  // Only send sources that actually ran — skip sources with missing API keys
  // or unsupported IOC types so the client never sees "SKIPPED" rows.
  const visibleResults = results.filter(r => !r.skipped);

  const riskFactors = collectRiskFactors(results);
  const { baseline, floor, bonus, confidence } = calcConfidenceWithFloors(results, riskFactors);
  const activeWeights = results
    .filter(r => !r.skipped && !r.error && r.verdict !== undefined)
    .reduce((sum, r) => sum + r.weight, 0);

  // Fire-and-forget MALICIOUS alert (per-user webhook, else env fallback) —
  // does not block or fail the scan response.
  if (Number.isFinite(confidence)) {
    maybeFireAlert(req, ioc, type, confidence, riskFactors).catch(() => {});
  }

  // Telemetry: log each source that actually performed an external call. The IP
  // VirusTotal result is reused from vt.js's cache (no call here), so it's logged
  // by vt.js, not double-counted here.
  logApiUsage(
    req,
    results
      .filter(r => !r.skipped && !(r.source === 'VirusTotal' && type === 'ip'))
      .map(r => ({
        service: r.source,
        ioc_type: type,
        outcome: r.error ? (/rate limit|429|quota/i.test(r.error) ? 'rate_limited' : 'error') : 'ok',
      }))
  ).catch(() => {});

  return res.status(200).json({
    ioc,
    type,
    confidence,
    baselineConfidence: baseline,
    floor,
    bonus,
    activeWeights,
    riskFactors,
    sources: visibleResults,
  });
};

// Exposed for unit tests.
module.exports.collectRiskFactors = collectRiskFactors;
module.exports.calcConfidenceWithFloors = calcConfidenceWithFloors;
module.exports.checkEnrichment = checkEnrichment;
module.exports.checkURLScan = checkURLScan;
