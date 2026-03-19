const https = require('https');

function getVTKeys() {
  const keys = [];
  const k1 = process.env.VT_API_KEY;
  if (k1) keys.push(k1);
  for (let i = 2; i <= 10; i++) {
    const k = process.env[`VT_API_KEY_${i}`];
    if (k) keys.push(k);
  }
  return keys;
}

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
        catch (e) { reject(new Error('Parse error: ' + body.slice(0, 100))); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpPost(url, postBody, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: 'POST',
      headers: {
        ...headers
      }
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body) }); }
        catch (e) { reject(new Error('Parse error: ' + body.slice(0, 120))); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(postBody);
    req.end();
  });
}

// ── IOC utils ────────────────────────────────────────────────────────────
function extractIOC(raw) {
  let s = raw.trim();
  s = s.replace(/^\[|\]$/g, '');
  s = s.replace(/^hxxps?/i, 'https');
  s = s.replace(/\[\.\]/g, '.').replace(/\(dot\)/gi, '.');
  if (/^https?:\/\//i.test(s)) {
    try { s = new URL(s).hostname; }
    catch { s = s.replace(/^https?:\/\//i, '').split('/')[0]; }
  }
  s = s.split('/')[0].split('?')[0].split('#')[0];
  s = s.replace(/:(\d+)$/, '').replace(/\.$/, '');
  return s.toLowerCase();
}

function detectType(s) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ip';
  if (/^[0-9a-f:]{3,39}$/.test(s) && s.includes(':') && s.split(':').length >= 3) return 'ip';
  if (/^[0-9a-f]+$/.test(s) && [32,40,56,64,96,128].includes(s.length)) return 'hash';
  if (/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/.test(s)) return 'domain';
  return null;
}

function getTrustFactor(envKey, defaultValue = 1) {
  const raw = process.env[envKey];
  if (raw === undefined || raw === null || raw === '') return defaultValue;
  const n = Number.parseFloat(raw);
  if (!Number.isFinite(n) || n < 0) return defaultValue;
  return n;
}

// ── Source: VirusTotal ────────────────────────────────────────────────────
async function checkVT(ioc, type) {
  const keys = getVTKeys();
  if (!keys.length) return { source: 'VirusTotal', skipped: true, reason: 'No API key' };

  const urlMap = {
    hash:   `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
    ip:     `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
    domain: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`,
  };
  const url = urlMap[type];
  if (!url) return { source: 'VirusTotal', skipped: true, reason: `Unsupported type: ${type}` };

  let lastError = null;
  let rateLimitedCount = 0;

  for (const key of keys) {
    try {
      const { status, data } = await httpGet(url, {
        'x-apikey': key, 'Accept': 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0'
      });
      if (status === 429) {
        rateLimitedCount++;
        continue;
      }
      if (status !== 200) return { source: 'VirusTotal', error: data?.error?.message || `HTTP ${status}` };

      const s   = data.data?.attributes?.last_analysis_stats || {};
      const mal = s.malicious  || 0;
      const sus = s.suspicious || 0;
      const total = Object.values(s).reduce((a, b) => a + b, 0);
      const ratio = total > 0 ? (mal + sus) / total : 0;
      const score = Math.round(ratio * 100);
      const verdict = mal >= 5 ? 'malicious' : (mal > 0 || sus > 3) ? 'suspicious' : total === 0 ? 'unknown' : 'clean';

      const vtUrlMap = {
        hash: `https://www.virustotal.com/gui/file/${ioc}`,
        ip:   `https://www.virustotal.com/gui/ip-address/${ioc}`,
        domain: `https://www.virustotal.com/gui/domain/${ioc}`,
      };

      return {
        source:  'VirusTotal',
        verdict,
        score,
        weight:  0.25 * getTrustFactor('TRUST_VT'),
        meta: {
          'Malicious':  mal,
          'Suspicious': sus,
          'Undetected': s.undetected || 0,
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
  return { source: 'VirusTotal', error: `Cannot access VirusTotal: ${lastError?.message || 'Unknown error'}` };
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
    if (status !== 200) return { source: 'AbuseIPDB', error: `AbuseIPDB: ${data?.errors?.[0]?.detail || `HTTP ${status}`}` };
    const d = data.data;
    const score = d.abuseConfidenceScore || 0;
    return {
      source:  'AbuseIPDB',
      verdict: score >= 80 ? 'malicious' : score >= 25 ? 'suspicious' : 'clean',
      score,
      weight:  0.25 * getTrustFactor('TRUST_ABUSEIPDB'),
      meta: {
        'Abuse Score':   score + '%',
        'Total Reports': d.totalReports,
        'Last Reported': d.lastReportedAt ? d.lastReportedAt.slice(0, 10) : '—',
        'ISP':           d.isp || '—',
        'Usage Type':    d.usageType || '—',
        'Country':       d.countryCode || '—',
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
    const { status, data } = await httpPost(
      `https://urlhaus-api.abuse.ch/v1/host/`,
      postBody,
      {
        'Auth-Key': apiKey,
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Charlie-kerennnn/1.0'
      }
    );

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
    const urlCount = data?.url_count !== undefined && data?.url_count !== null
      ? Number(data.url_count)
      : urls.length;
    const onlineUrls = urls.filter(u => u?.url_status === 'online').length;
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
  if (!otxType) return { source: 'AlienVault OTX', skipped: true, reason: `Unsupported type: ${type}` };
  try {
    const { status, data } = await httpGet(
      `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`,
      { 'X-OTX-API-KEY': apiKey, Accept: 'application/json' }
    );
    if (status !== 200) return { source: 'AlienVault OTX', error: `OTX: HTTP ${status}` };
    const pulseCount = data.pulse_info?.count || 0;
    const verdict    = pulseCount >= 5 ? 'malicious' : pulseCount >= 1 ? 'suspicious' : 'clean';
    return {
      source:  'AlienVault OTX',
      verdict,
      score:   Math.min(pulseCount * 10, 100),
      weight:  0.25 * getTrustFactor('TRUST_OTX'),
      meta: {
        'Pulse Count':      pulseCount,
        'Reputation':       data.reputation ?? '—',
        'Type Tags':        (data.type_tags || []).slice(0, 3).join(', ') || '—',
        'Malware Families': (data.pulse_info?.related?.malware_families || []).slice(0, 2).join(', ') || '—',
      },
      link: `https://otx.alienvault.com/indicator/${otxType}/${ioc}`,
    };
  } catch (e) {
    return { source: 'AlienVault OTX', error: `Cannot access OTX: ${e.message}` };
  }
}

// ── Source: GreyNoise ─────────────────────────────────────────────────────
async function checkGreyNoise(ip) {
  const apiKey = process.env.GREYNOISE_API_KEY;
  if (!apiKey) return { source: 'GreyNoise', skipped: true, reason: 'No API key' };
  try {
    const { status, data } = await httpGet(
      `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
      { key: apiKey, Accept: 'application/json' }
    );
    if (status === 404) {
      return {
        source: 'GreyNoise', verdict: 'unknown', score: 0, weight: 0.20,
        meta: { 'Status': 'Not seen', 'Noise': 'No', 'RIOT': 'No' },
        link: `https://viz.greynoise.io/ip/${ip}`,
      };
    }
    if (status !== 200) return { source: 'GreyNoise', error: `GreyNoise: ${data?.message || `HTTP ${status}`}` };
    const cls     = data.classification || 'unknown';
    const verdict = data.riot ? 'clean' : cls === 'malicious' ? 'malicious' : cls === 'benign' ? 'clean' : 'unknown';
    return {
      source:  'GreyNoise',
      verdict,
      score:   verdict === 'malicious' ? 80 : verdict === 'clean' ? 0 : 30,
      weight:  0.20,
      meta: {
        'Classification': cls,
        'Noise':          data.noise ? 'Yes (scanner)' : 'No',
        'RIOT':           data.riot  ? 'Yes (known safe)' : 'No',
        'Name':           data.name || '—',
      },
      link: `https://viz.greynoise.io/ip/${ip}`,
    };
  } catch (e) {
    return { source: 'GreyNoise', error: `Cannot access GreyNoise: ${e.message}` };
  }
}

// ── Weighted confidence score ─────────────────────────────────────────────
// verdictScore maps verdict → risk level 0.0–1.0
// unknown gets 0.2 (slight risk, not zero) so it still nudges the score
function calcConfidence(results) {
  const verdictScore = { malicious: 1.0, suspicious: 0.5, unknown: 0.2, clean: 0.0 };
  let weightedSum = 0;
  let totalWeight = 0;
  for (const r of results) {
    if (r.skipped || r.error || r.verdict === undefined) continue;
    const vs = verdictScore[r.verdict] ?? 0;
    weightedSum += vs * r.weight;
    totalWeight += r.weight;
  }
  if (totalWeight === 0) return null;
  return Math.round((weightedSum / totalWeight) * 100);
}

// ── Handler ───────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ioc: rawIoc } = req.query;
  if (!rawIoc) return res.status(400).json({ error: 'Missing ?ioc= param.' });

  const ioc  = extractIOC(rawIoc);
  const type = detectType(ioc);
  if (!type) return res.status(400).json({ error: `Cannot detect IOC type for: "${ioc}"` });

  // Build check list based on IOC type
  const checks = [ checkVT(ioc, type) ];                          // all types
  if (type === 'ip') checks.push(checkAbuseIPDB(ioc));            // IP only
  if (type === 'ip' || type === 'domain') checks.push(checkAbuseCh(ioc)); // Abuse.ch (URLhaus) host query
  checks.push(checkOTX(ioc, type));                               // all types

  const results    = await Promise.all(checks);
  const confidence = calcConfidence(results);

  // Total weights of active (non-skipped, non-error) sources
  const activeWeights = results
    .filter(r => !r.skipped && !r.error && r.verdict !== undefined)
    .reduce((sum, r) => sum + r.weight, 0);

  return res.status(200).json({ ioc, type, confidence, activeWeights, sources: results });
};