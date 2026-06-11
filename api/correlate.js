'use strict';
const { extractIOC, detectType } = require('./_ioc');
const { httpGet, httpPost } = require('./_http');
const { getVtKeysForRequest, shouldTryNextVtKey, isVtRateLimited, isVtBadKey } = require('./_vtkeys');
const { getAbuseIPDBKeys } = require('./_abuseipdbkeys');
const { requireAuth } = require('./_auth');
const { getSupabase } = require('./_supabase');

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
        if (isVtRateLimited(status, data)) rateLimitedCount++;
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

// ── Source: GreyNoise (weight 0.25, IP only) ──────────────────────────────
// Classifies whether an IP is internet background noise vs. targeted.
// riot=true means it's a known-good service (Google, Cloudflare, etc.) → always clean.
async function checkGreyNoise(ip) {
  const apiKey = process.env.GREYNOISE_API_KEY;
  if (!apiKey) return { source: 'GreyNoise', skipped: true, reason: 'No API key' };
  try {
    const { status, data } = await httpGet(
      `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
      { key: apiKey, Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' }
    );
    if (status === 404) {
      return {
        source: 'GreyNoise',
        verdict: 'clean',
        score: 0,
        weight: 0.25 * getTrustFactor('TRUST_GREYNOISE'),
        meta: { Classification: 'not observed', Note: 'IP not in GreyNoise dataset' },
        link: `https://viz.greynoise.io/ip/${ip}`,
      };
    }
    if (status !== 200) return { source: 'GreyNoise', error: `GreyNoise: HTTP ${status}` };

    const riot = data.riot ?? false;
    const noise = data.noise ?? false;
    const classification = data.classification || 'unknown';
    const name = data.name || '';

    let verdict, score;
    if (riot) {
      verdict = 'clean'; score = 0;
    } else if (noise && classification === 'malicious') {
      verdict = 'malicious'; score = 85;
    } else if (noise) {
      // Benign/unknown scanner — internet background noise, context only
      verdict = 'suspicious'; score = 25;
    } else {
      verdict = 'clean'; score = 0;
    }

    return {
      source: 'GreyNoise',
      verdict,
      score,
      weight: 0.25 * getTrustFactor('TRUST_GREYNOISE'),
      meta: {
        Classification: classification || '—',
        'RIOT (trusted service)': riot ? 'yes' : 'no',
        'Internet Scanner': noise ? 'yes' : 'no',
        Name: name || '—',
      },
      link: `https://viz.greynoise.io/ip/${ip}`,
    };
  } catch (e) {
    return { source: 'GreyNoise', error: `Cannot access GreyNoise: ${e.message}` };
  }
}

// ── Source: MalwareBazaar — Abuse.ch (weight 0.25, hash only, no key) ────
async function checkMalwareBazaar(hash) {
  try {
    const postBody = `query=get_info&hash=${encodeURIComponent(hash)}`;
    const { status, data } = await httpPost(
      'https://mb-api.abuse.ch/api/v1/',
      postBody,
      { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Charlie-kerennnn/1.0' }
    );
    if (status !== 200) return { source: 'MalwareBazaar', error: `MalwareBazaar: HTTP ${status}` };

    if (data.query_status === 'hash_not_found') {
      return {
        source: 'MalwareBazaar',
        verdict: 'clean',
        score: 0,
        weight: 0.25 * getTrustFactor('TRUST_MALWAREBAZAAR'),
        meta: { Result: 'Not found in MalwareBazaar' },
        link: `https://bazaar.abuse.ch/browse.php?search=sha256:${hash}`,
      };
    }

    const item = Array.isArray(data.data) ? data.data[0] : null;
    if (!item) return { source: 'MalwareBazaar', error: 'Unexpected response format' };

    return {
      source: 'MalwareBazaar',
      verdict: 'malicious',
      score: 100,
      weight: 0.25 * getTrustFactor('TRUST_MALWAREBAZAAR'),
      meta: {
        'Malware Family': item.signature || '—',
        'File Type': item.file_type || '—',
        Tags: (item.tags || []).slice(0, 4).join(', ') || '—',
        'First Seen': item.first_seen ? item.first_seen.slice(0, 10) : '—',
        Reporter: item.reporter || '—',
      },
      link: `https://bazaar.abuse.ch/sample/${hash}/`,
    };
  } catch (e) {
    return { source: 'MalwareBazaar', error: `Cannot access MalwareBazaar: ${e.message}` };
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

// ── Source: Shodan (context-only, no verdict/weight, IP only) ─────────────
// Contributes to score only via risk factors (exposed ports, known CVEs).
async function checkShodan(ip) {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return { source: 'Shodan', skipped: true, reason: 'No API key' };
  try {
    const { status, data } = await httpGet(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`,
      { Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' }
    );
    if (status === 404) return { source: 'Shodan', skipped: true, reason: 'IP not in Shodan index' };
    if (status !== 200) return { source: 'Shodan', error: `Shodan: HTTP ${status}` };

    const ports = (data.ports || []).slice(0, 10);
    const vulns = Object.keys(data.vulns || {}).slice(0, 5);

    return {
      source: 'Shodan',
      // no verdict / weight — context source like Enrichment
      meta: {
        'Open Ports': ports.join(', ') || '—',
        'Known CVEs': vulns.join(', ') || '—',
        Org: data.org || data.isp || '—',
        OS: data.os || '—',
        Country: data.country_code || '—',
      },
      link: `https://www.shodan.io/host/${ip}`,
    };
  } catch (e) {
    return { source: 'Shodan', error: `Cannot access Shodan: ${e.message}` };
  }
}

// ── Source: Pulsedive (weight 0.10, all types) ────────────────────────────
async function checkPulsedive(ioc) {
  const apiKey = process.env.PULSEDIVE_API_KEY;
  if (!apiKey) return { source: 'Pulsedive', skipped: true, reason: 'No API key' };
  try {
    const { status, data } = await httpGet(
      `https://pulsedive.com/api/info.php?indicator=${encodeURIComponent(ioc)}&pretty=1&key=${encodeURIComponent(apiKey)}`,
      { Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' }
    );
    if (status === 404 || data?.error === 'Indicator not found.') {
      return {
        source: 'Pulsedive',
        verdict: 'clean',
        score: 0,
        weight: 0.10 * getTrustFactor('TRUST_PULSEDIVE'),
        meta: { Result: 'Not found in Pulsedive' },
        link: `https://pulsedive.com/indicator/?ioc=${encodeURIComponent(ioc)}`,
      };
    }
    if (status !== 200) return { source: 'Pulsedive', error: `Pulsedive: HTTP ${status}` };

    const riskMap  = { none: 'clean', low: 'clean', medium: 'suspicious', high: 'malicious', critical: 'malicious' };
    const scoreMap = { none: 0, low: 10, medium: 40, high: 75, critical: 95 };
    const risk = (data.risk || 'none').toLowerCase();

    return {
      source: 'Pulsedive',
      verdict: riskMap[risk] || 'clean',
      score: scoreMap[risk] || 0,
      weight: 0.10 * getTrustFactor('TRUST_PULSEDIVE'),
      meta: {
        Risk: data.risk || '—',
        'Threat Types': (data.threats || []).slice(0, 3).map(t => t.name).join(', ') || '—',
        'Last Seen': data.lastseen ? data.lastseen.slice(0, 10) : '—',
      },
      link: `https://pulsedive.com/indicator/?ioc=${encodeURIComponent(ioc)}`,
    };
  } catch (e) {
    return { source: 'Pulsedive', error: `Cannot access Pulsedive: ${e.message}` };
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

    if (r.source === 'GreyNoise') {
      const isScanner = m['Internet Scanner'] === 'yes';
      const classification = String(m.Classification || '').toLowerCase();
      if (isScanner && classification === 'malicious') {
        factors.push({ type: 'greynoise_malicious', severity: 'high', source: 'GreyNoise', message: 'Known malicious internet scanner (GreyNoise)', bonus: 15 });
      } else if (isScanner) {
        factors.push({ type: 'greynoise_noise', severity: 'low', source: 'GreyNoise', message: 'Internet background noise scanner (GreyNoise)', bonus: 3 });
      }
    }

    if (r.source === 'MalwareBazaar' && r.verdict === 'malicious') {
      const family = String(m['Malware Family'] || '—');
      factors.push({
        type: 'malware_sample',
        severity: 'high',
        source: 'MalwareBazaar',
        message: `Confirmed malware sample${family !== '—' ? ': ' + family : ''}`,
        bonus: 20,
      });
    }

    if (r.source === 'URLScan.io') {
      if (r.verdict === 'malicious') {
        factors.push({ type: 'urlscan_malicious', severity: 'high', source: 'URLScan.io', message: 'URLScan.io flagged page as malicious', bonus: 12 });
      }
      if (String(m.Tags || '').toLowerCase().includes('phishing')) {
        factors.push({ type: 'urlscan_phishing', severity: 'high', source: 'URLScan.io', message: 'Phishing page detected by URLScan.io', bonus: 12 });
      }
    }

    if (r.source === 'Shodan') {
      const riskyPorts = String(m['Open Ports'] || '').split(',').map(p => p.trim())
        .filter(p => ['22', '23', '445', '3389', '4444', '5900'].includes(p));
      if (riskyPorts.length > 0) {
        factors.push({ type: 'exposed_ports', severity: 'med', source: 'Shodan', message: `Exposed risky ports: ${riskyPorts.join(', ')}`, bonus: 8 });
      }
      const vulns = String(m['Known CVEs'] || '').trim();
      if (vulns && vulns !== '—') {
        factors.push({ type: 'known_vulns', severity: 'high', source: 'Shodan', message: `Known CVEs: ${vulns.split(',').slice(0, 2).join(', ')}`, bonus: 15 });
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

  // Fix 1: Abuse.ch/MalwareBazaar draw from the same dataset — cap their
  // combined effective weight at 0.30 to prevent correlated-source inflation.
  const ABUSE_CH_GROUP = new Set(['Abuse.ch', 'MalwareBazaar']);
  const ABUSE_CH_CAP = 0.30;
  let groupRawWeight = 0;
  for (const r of results) {
    if (!r.skipped && !r.error && r.verdict !== undefined && ABUSE_CH_GROUP.has(r.source))
      groupRawWeight += r.weight;
  }
  const groupScale = groupRawWeight > ABUSE_CH_CAP ? ABUSE_CH_CAP / groupRawWeight : 1;
  const effectiveWeight = r => ABUSE_CH_GROUP.has(r.source) ? r.weight * groupScale : r.weight;

  let weightedSum = 0;
  let totalWeight = 0;
  let maliciousWeight = 0;
  let suspiciousWeight = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  for (const r of results) {
    if (r.skipped || r.error || r.verdict === undefined) continue;
    const w = effectiveWeight(r);
    const vs = verdictScore[r.verdict] ?? 0;
    weightedSum += vs * w;
    totalWeight += w;
    if (r.verdict === 'malicious') { maliciousWeight += w; maliciousCount++; }
    else if (r.verdict === 'suspicious') { suspiciousWeight += w; suspiciousCount++; }
  }
  if (totalWeight === 0) return { baseline: null, floor: 0, bonus: 0, confidence: null };
  const baseline = Math.round((weightedSum / totalWeight) * 100);

  // Fix 2: Trust-weighted floors — dual condition (absolute weight OR ratio of active weight)
  // so sparse configs (e.g. VT-only) still produce the right floor without over-triggering
  // for low-trust-only source combinations.
  const maliciousRatio = maliciousWeight / totalWeight;
  const suspiciousRatio = suspiciousWeight / totalWeight;
  let floor = 0;
  if      (maliciousWeight >= 0.50 || (maliciousRatio >= 0.60 && maliciousCount >= 2))   floor = 70;
  else if (maliciousWeight >= 0.20 || (maliciousRatio >= 0.50 && maliciousCount >= 1))   floor = 40;
  else if (suspiciousWeight >= 0.50 || (suspiciousRatio >= 0.60 && suspiciousCount >= 2)) floor = 40;
  else if (suspiciousWeight >= 0.25 || (suspiciousRatio >= 0.40 && suspiciousCount >= 1)) floor = 25;

  // Fix 3: Hard signal overrides — ground-truth verdicts that override probabilistic floors.
  // MalwareBazaar: confirmed malware sample DB hit. GreyNoise malicious: confirmed internet scanner.
  for (const r of results) {
    if (r.skipped || r.error) continue;
    if (r.source === 'MalwareBazaar' && r.verdict === 'malicious') floor = Math.max(floor, 85);
    if (r.source === 'GreyNoise'     && r.verdict === 'malicious') floor = Math.max(floor, 65);
  }

  const bonus = Math.min((factors || []).reduce((sum, f) => sum + (f.bonus || 0), 0), 25);
  let confidence = Math.min(100, Math.max(baseline, floor) + bonus);

  // GreyNoise RIOT exoneration — IP is a trusted internet service (Google, Cloudflare, etc.);
  // cap confidence at 15 regardless of what other sources say.
  const riot = results.find(
    r => !r.skipped && !r.error && r.source === 'GreyNoise' && r.meta?.['RIOT (trusted service)'] === 'yes'
  );
  if (riot) confidence = Math.min(confidence, 15);

  return { baseline, floor, bonus, confidence };
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
    checkPulsedive(ioc),       // all types
  ];

  if (type === 'ip') {
    checks.push(checkAbuseIPDB(ioc));
    checks.push(checkGreyNoise(ioc));
    checks.push(checkShodan(ioc));
  }

  if (type === 'ip' || type === 'domain') {
    checks.push(checkAbuseCh(ioc));
    checks.push(checkEnrichment(ioc, type));
  }

  if (type === 'domain') checks.push(checkURLScan(ioc));
  if (type === 'hash')   checks.push(checkMalwareBazaar(ioc));

  const results = await Promise.all(checks);

  // Only send sources that actually ran — skip sources with missing API keys
  // or unsupported IOC types so the client never sees "SKIPPED" rows.
  const visibleResults = results.filter(r => !r.skipped);

  const riskFactors = collectRiskFactors(results);
  const { baseline, floor, bonus, confidence } = calcConfidenceWithFloors(results, riskFactors);
  const activeWeights = results
    .filter(r => !r.skipped && !r.error && r.verdict !== undefined)
    .reduce((sum, r) => sum + r.weight, 0);

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
module.exports.checkGreyNoise = checkGreyNoise;
module.exports.checkMalwareBazaar = checkMalwareBazaar;
module.exports.checkURLScan = checkURLScan;
module.exports.checkShodan = checkShodan;
module.exports.checkPulsedive = checkPulsedive;
