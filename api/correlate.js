const { extractIOC, detectType } = require('./_ioc');
const { httpGet, httpPost } = require('./_http');
const { getVtKeys } = require('./_vtkeys');
const { requireAuth } = require('./_auth');

function getTrustFactor(envKey, defaultValue = 1) {
  const raw = process.env[envKey];
  if (raw === undefined || raw === null || raw === '') return defaultValue;
  const n = Number.parseFloat(raw);
  if (!Number.isFinite(n) || n < 0) return defaultValue;
  return n;
}

// ── High-risk hosting providers (commonly abused for malicious infra) ─────
// Substring match, case-insensitive, against AbuseIPDB `isp` field.
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

// ── Source: VirusTotal ────────────────────────────────────────────────────
async function checkVT(ioc, type) {
  const keys = getVtKeys();
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

  for (const key of keys) {
    try {
      const { status, data } = await httpGet(url, {
        'x-apikey': key,
        Accept: 'application/json',
        'User-Agent': 'Charlie-kerennnn/1.0',
      });
      if (status === 429) {
        rateLimitedCount++;
        continue;
      }
      if (status !== 200)
        return { source: 'VirusTotal', error: data?.error?.message || `HTTP ${status}` };

      const s = data.data?.attributes?.last_analysis_stats || {};
      const mal = s.malicious || 0;
      const sus = s.suspicious || 0;
      const total = Object.values(s).reduce((a, b) => a + b, 0);
      const ratio = total > 0 ? (mal + sus) / total : 0;
      const score = Math.round(ratio * 100);
      // More sensitive: any malicious detection raises alarm; use ratio for high-density flagging.
      const verdict =
        (mal >= 5 || score >= 10)
          ? 'malicious'
          : (mal >= 1 || sus >= 3 || score >= 5)
            ? 'suspicious'
            : total === 0
              ? 'unknown'
              : 'clean';

      const vtUrlMap = {
        hash: `https://www.virustotal.com/gui/file/${ioc}`,
        ip: `https://www.virustotal.com/gui/ip-address/${ioc}`,
        domain: `https://www.virustotal.com/gui/domain/${ioc}`,
      };

      return {
        source: 'VirusTotal',
        verdict,
        score,
        weight: 0.25 * getTrustFactor('TRUST_VT'),
        meta: {
          Malicious: mal,
          Suspicious: sus,
          Undetected: s.undetected || 0,
          'Total Engines': total,
          'Detection %': score + '%',
        },
        link: vtUrlMap[type],
      };
    } catch (e) {
      lastError = e;
      continue;
    }
  }

  if (rateLimitedCount === keys.length) {
    return { source: 'VirusTotal', error: 'All keys rate limited. Try again later.' };
  }
  return {
    source: 'VirusTotal',
    error: `Cannot access VirusTotal: ${lastError?.message || 'Unknown error'}`,
  };
}

// ── Source: AbuseIPDB ─────────────────────────────────────────────────────
async function checkAbuseIPDB(ip) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return { source: 'AbuseIPDB', skipped: true, reason: 'No API key' };
  try {
    const { status, data } = await httpGet(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { Key: apiKey, Accept: 'application/json' }
    );
    if (status !== 200)
      return {
        source: 'AbuseIPDB',
        error: `AbuseIPDB: ${data?.errors?.[0]?.detail || `HTTP ${status}`}`,
      };
    const d = data.data;
    const score = d.abuseConfidenceScore || 0;
    const reports = d.totalReports || 0;
    // Reports boost the confidence score as an amplifier, not an independent trigger.
    // This prevents 0% confidence + 30 reports from jumping straight to malicious.
    const reportBoost = reports >= 25 ? 20 : reports >= 10 ? 10 : reports >= 3 ? 5 : 0;
    const adjustedScore = Math.min(100, score + reportBoost);
    const verdict =
      adjustedScore >= 50 ? 'malicious' :
      adjustedScore >= 20 ? 'suspicious' :
      'clean';
    return {
      source: 'AbuseIPDB',
      verdict,
      score,
      weight: 0.25 * getTrustFactor('TRUST_ABUSEIPDB'),
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
    return { source: 'AbuseIPDB', error: `Cannot access AbuseIPDB: ${e.message}` };
  }
}

// ── Source: Abuse.ch (URLhaus) ─────────────────────────────────────────
async function checkAbuseCh(ioc) {
  // URLhaus (abuse.ch) API key is typically provided via "Auth-Key" header.
  const apiKey = process.env.ABUSECH_API_KEY || process.env.URLHAUS_API_KEY;
  if (!apiKey) return { source: 'Abuse.ch', skipped: true, reason: 'No API key' };

  try {
    // URLhaus "host" query uses HTTP POST with body: host=<host>
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
        weight: 0.25 * getTrustFactor('TRUST_ABUSECH'),
        meta: { 'URL Count': 0, 'Online URLs': 0, 'First Seen': '—' },
        link: `https://urlhaus.abuse.ch/host/${encodeURIComponent(ioc)}/`,
      };
    }

    const urls = Array.isArray(data?.urls) ? data.urls : [];
    const urlCount =
      data?.url_count !== undefined && data?.url_count !== null
        ? Number(data.url_count)
        : urls.length;
    const onlineUrls = urls.filter((u) => u?.url_status === 'online').length;
    const firstSeen = data?.firstseen || '—';

    const verdict = onlineUrls > 0 ? 'malicious' : urlCount > 0 ? 'suspicious' : 'clean';
    const score = verdict === 'malicious' ? 80 : verdict === 'suspicious' ? 40 : 0;

    return {
      source: 'Abuse.ch',
      verdict,
      score,
      weight: 0.25 * getTrustFactor('TRUST_ABUSECH'),
      meta: {
        'URL Count': urlCount || 0,
        'Online URLs': onlineUrls,
        'First Seen': firstSeen,
      },
      link: data?.urlhaus_reference || `https://urlhaus.abuse.ch/host/${encodeURIComponent(ioc)}/`,
    };
  } catch (e) {
    return { source: 'Abuse.ch', error: `Cannot access Abuse.ch (URLhaus): ${e.message}` };
  }
}

// ── Source: AlienVault OTX ────────────────────────────────────────────────
async function checkOTX(ioc, type) {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) return { source: 'AlienVault OTX', skipped: true, reason: 'No API key' };
  const typeMap = { ip: 'IPv4', domain: 'domain', hash: 'file' };
  const otxType = typeMap[type];
  if (!otxType)
    return { source: 'AlienVault OTX', skipped: true, reason: `Unsupported type: ${type}` };
  try {
    const { status, data } = await httpGet(
      `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`,
      { 'X-OTX-API-KEY': apiKey, Accept: 'application/json' }
    );
    if (status !== 200) return { source: 'AlienVault OTX', error: `OTX: HTTP ${status}` };
    const pulseCount = data.pulse_info?.count || 0;
    const families = data.pulse_info?.related?.malware_families || [];
    const pulses = data.pulse_info?.pulses || [];
    const recentPulse = pulses.some((p) => {
      const ts = p.modified || p.created;
      if (!ts) return false;
      const days = (Date.now() - new Date(ts).getTime()) / 86400000;
      return Number.isFinite(days) && days <= 30;
    });
    // Recency + malware family weight more than raw count.
    const verdict =
      (pulseCount >= 5 || (families.length > 0 && recentPulse))
        ? 'malicious'
        : pulseCount >= 1
          ? 'suspicious'
          : 'clean';
    return {
      source: 'AlienVault OTX',
      verdict,
      score: Math.min(pulseCount * 10 + (recentPulse ? 10 : 0) + (families.length > 0 ? 10 : 0), 100),
      weight: 0.25 * getTrustFactor('TRUST_OTX'),
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

// ── Source: Enrichment (RDAP + GeoIP) ─────────────────────────────────────
// Context source: registration age / registrar / ASN / org / geo. Carries NO
// `verdict`/`weight`, so calcConfidenceWithFloors skips it and it never dilutes
// the weighted baseline — it contributes to the score only via risk factors.
// All requests are server-side with fixed host+protocol (no SSRF surface).
function extractRdapEntityName(entity) {
  // RDAP entities carry a jCard: vcardArray = ["vcard", [ ["fn",{},"text","Name"], ... ]]
  try {
    const vcard = entity && entity.vcardArray && entity.vcardArray[1];
    if (Array.isArray(vcard)) {
      const fn = vcard.find((f) => Array.isArray(f) && f[0] === 'fn');
      if (fn && fn[3]) return String(fn[3]);
    }
  } catch {
    // ignore malformed vcard
  }
  return entity && entity.handle ? String(entity.handle) : null;
}

async function checkEnrichment(ioc, type) {
  if (type !== 'ip' && type !== 'domain') {
    return { source: 'Enrichment', skipped: true, reason: `Unsupported type: ${type}` };
  }
  const meta = {};

  // ── RDAP (no API key): registration age, registrar, RIR country/handle ──
  try {
    const path = type === 'ip' ? `ip/${encodeURIComponent(ioc)}` : `domain/${encodeURIComponent(ioc)}`;
    const { status, data } = await httpGet(
      `https://rdap.org/${path}`,
      { Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' },
      { timeout: 7000 }
    );
    if (status === 200 && data && typeof data === 'object') {
      const events = Array.isArray(data.events) ? data.events : [];
      const reg = events.find((e) => e && e.eventAction === 'registration');
      if (reg && reg.eventDate) {
        const t = new Date(reg.eventDate).getTime();
        meta.Registered = String(reg.eventDate).slice(0, 10);
        if (Number.isFinite(t)) meta['Age (days)'] = Math.max(0, Math.floor((Date.now() - t) / 86400000));
      }
      const entities = Array.isArray(data.entities) ? data.entities : [];
      const registrar = entities.find((e) => Array.isArray(e?.roles) && e.roles.includes('registrar'));
      const regName = registrar && extractRdapEntityName(registrar);
      if (regName) meta.Registrar = regName;
      if (data.country) meta['RIR Country'] = data.country;
      if (data.handle) meta['Handle/CIDR'] = data.handle;
    }
  } catch {
    // best-effort — enrichment never blocks the verdict
  }

  // ── GeoIP (ip only): ipinfo.io when IPINFO_TOKEN set, else ipwho.is (no key) ──
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
          if (data.org) {
            meta.Org = data.org;
            meta.ASN = String(data.org).split(' ')[0]; // ipinfo org is "AS#### Name"
          }
          meta.GeoSource = 'ipinfo.io';
        }
      } else {
        const { status, data } = await httpGet(`https://ipwho.is/${encodeURIComponent(ioc)}`, {
          Accept: 'application/json',
        });
        if (status === 200 && data && data.success !== false) {
          if (data.country_code) meta.Country = data.country_code;
          if (data.city) meta.City = data.city;
          const conn = data.connection || {};
          if (conn.org || conn.isp) meta.Org = conn.org || conn.isp;
          if (conn.asn) meta.ASN = 'AS' + conn.asn;
          meta.GeoSource = 'ipwho.is';
        }
      }
    } catch {
      // best-effort
    }
  }

  if (Object.keys(meta).length === 0) {
    return { source: 'Enrichment', skipped: true, reason: 'No enrichment data available' };
  }
  return {
    source: 'Enrichment',
    meta,
    link: type === 'ip' ? `https://rdap.org/ip/${ioc}` : `https://rdap.org/domain/${ioc}`,
  };
}

// ── Risk factor collection ────────────────────────────────────────────────
// Each factor: { type, severity ('high'|'med'|'low'), source, message, bonus }
function collectRiskFactors(results) {
  const factors = [];
  for (const r of results) {
    if (r.skipped || r.error) continue;
    const m = r.meta || {};

    if (r.source === 'VirusTotal') {
      const mal = Number(m.Malicious) || 0;
      if (mal >= 1) {
        const total = Number(m['Total Engines']) || 0;
        factors.push({
          type: 'vt_detection',
          severity: mal >= 5 ? 'high' : 'med',
          source: 'VirusTotal',
          message: `${mal}/${total} engine flag malicious`,
          bonus: mal >= 5 ? 10 : 5,
        });
      }
    }

    if (r.source === 'AbuseIPDB') {
      const reports = Number(m['Total Reports']) || 0;
      if (reports >= 25) {
        factors.push({
          type: 'many_reports',
          severity: 'high',
          source: 'AbuseIPDB',
          message: `${reports} laporan abuse (90 hari)`,
          bonus: 15,
        });
      } else if (reports >= 10) {
        factors.push({
          type: 'many_reports',
          severity: 'med',
          source: 'AbuseIPDB',
          message: `${reports} laporan abuse (90 hari)`,
          bonus: 10,
        });
      }
      const hoster = ispIsHighRiskHoster(m.ISP);
      if (hoster) {
        factors.push({
          type: 'hosting_provider',
          severity: 'med',
          source: 'AbuseIPDB',
          message: `Hosted di ${m.ISP} (sering disalahgunakan)`,
          bonus: 10,
        });
      }
      const usage = String(m['Usage Type'] || '').toLowerCase();
      if (
        !hoster &&
        (usage.includes('data center') ||
          usage.includes('hosting') ||
          usage.includes('colocrossing') ||
          usage.includes('transit'))
      ) {
        factors.push({
          type: 'datacenter_usage',
          severity: 'low',
          source: 'AbuseIPDB',
          message: `Usage type: ${m['Usage Type']}`,
          bonus: 5,
        });
      }
    }

    if (r.source === 'AlienVault OTX') {
      const families = String(m['Malware Families'] || '');
      if (families && families !== '—') {
        factors.push({
          type: 'malware_family',
          severity: 'high',
          source: 'AlienVault OTX',
          message: `Terkait keluarga malware: ${families}`,
          bonus: 10,
        });
      }
      if (m['Recent Pulse (<30d)'] === 'yes') {
        factors.push({
          type: 'recent_pulse',
          severity: 'med',
          source: 'AlienVault OTX',
          message: 'Pulse aktif dalam 30 hari terakhir',
          bonus: 5,
        });
      }
    }

    if (r.source === 'Abuse.ch') {
      const online = Number(m['Online URLs']) || 0;
      if (online > 0) {
        factors.push({
          type: 'urlhaus_online',
          severity: 'high',
          source: 'Abuse.ch',
          message: `${online} URL malicious aktif di URLhaus`,
          bonus: 10,
        });
      }
    }

    if (r.source === 'Enrichment') {
      const age = Number(m['Age (days)']);
      if (Number.isFinite(age)) {
        if (age < 30) {
          factors.push({
            type: 'new_registration',
            severity: 'high',
            source: 'Enrichment',
            message: `Baru didaftarkan (${age} hari lalu)`,
            bonus: 10,
          });
        } else if (age < 90) {
          factors.push({
            type: 'new_registration',
            severity: 'med',
            source: 'Enrichment',
            message: `Registrasi cukup baru (${age} hari lalu)`,
            bonus: 5,
          });
        }
      }
      const org = m.Org || m.ISP || m.ASN || '';
      const hoster = ispIsHighRiskHoster(org);
      if (hoster) {
        factors.push({
          type: 'hosting_provider',
          severity: 'med',
          source: 'Enrichment',
          message: `ASN/org sering disalahgunakan: ${org}`,
          bonus: 10,
        });
      }
    }
  }

  // Dedupe by factor type, keeping the highest-bonus instance — prevents an
  // AbuseIPDB + Enrichment 'hosting_provider' (or similar) from double-counting.
  const byType = new Map();
  for (const f of factors) {
    const prev = byType.get(f.type);
    if (!prev || (f.bonus || 0) > (prev.bonus || 0)) byType.set(f.type, f);
  }
  return [...byType.values()];
}

// ── Weighted confidence + risk floors + factor bonus ──────────────────────
// Prevents alarm dilution: a single confirmed source still raises verdict.
// verdictScore: malicious=1.0, suspicious=0.5, unknown=0.2, clean=0.0
function calcConfidenceWithFloors(results, factors) {
  const verdictScore = { malicious: 1.0, suspicious: 0.5, unknown: 0.2, clean: 0.0 };
  let weightedSum = 0;
  let totalWeight = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  for (const r of results) {
    if (r.skipped || r.error || r.verdict === undefined) continue;
    const vs = verdictScore[r.verdict] ?? 0;
    weightedSum += vs * r.weight;
    totalWeight += r.weight;
    if (r.verdict === 'malicious') maliciousCount++;
    else if (r.verdict === 'suspicious') suspiciousCount++;
  }
  if (totalWeight === 0) {
    return { baseline: null, floor: 0, bonus: 0, confidence: null };
  }
  const baseline = Math.round((weightedSum / totalWeight) * 100);

  // Risk floor: prevent strong single-source signals from being diluted.
  let floor = 0;
  if (maliciousCount >= 2) floor = 70;
  else if (maliciousCount >= 1) floor = 40;
  else if (suspiciousCount >= 3) floor = 40;
  else if (suspiciousCount >= 2) floor = 25;

  // Risk factor bonus, capped to avoid runaway scoring.
  const bonus = Math.min(
    (factors || []).reduce((sum, f) => sum + (f.bonus || 0), 0),
    25,
  );

  const confidence = Math.min(100, Math.max(baseline, floor) + bonus);
  return { baseline, floor, bonus, confidence };
}

// ── Handler ───────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Auth required: this endpoint spends the server's paid VT/AbuseIPDB/OTX keys.
  if (!requireAuth(req, res)) return;

  const { ioc: rawIoc } = req.query;
  if (!rawIoc) return res.status(400).json({ error: 'Missing ?ioc= param.' });

  const ioc = extractIOC(rawIoc);
  const type = detectType(ioc);
  if (!type) return res.status(400).json({ error: `Cannot detect IOC type for: "${ioc}"` });

  // Build check list based on IOC type
  const checks = [checkVT(ioc, type)]; // all types
  if (type === 'ip') checks.push(checkAbuseIPDB(ioc)); // IP only
  if (type === 'ip' || type === 'domain') checks.push(checkAbuseCh(ioc)); // Abuse.ch (URLhaus) host query
  checks.push(checkOTX(ioc, type)); // all types
  if (type === 'ip' || type === 'domain') checks.push(checkEnrichment(ioc, type)); // context + risk factors

  const results = await Promise.all(checks);
  const riskFactors = collectRiskFactors(results);
  const { baseline, floor, bonus, confidence } = calcConfidenceWithFloors(results, riskFactors);

  // Total weights of active (non-skipped, non-error) sources
  const activeWeights = results
    .filter((r) => !r.skipped && !r.error && r.verdict !== undefined)
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
    sources: results,
  });
};

// Exposed for unit tests (the handler is the default export above).
module.exports.collectRiskFactors = collectRiskFactors;
module.exports.calcConfidenceWithFloors = calcConfidenceWithFloors;
module.exports.checkEnrichment = checkEnrichment;
