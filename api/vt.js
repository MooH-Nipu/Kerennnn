const https = require('https');
const { createClient } = require('@supabase/supabase-js');
const { extractIOC, detectType } = require('./_ioc');
const { requireAuth } = require('./_auth');

function authEnabled() {
  return !!(process.env.APP_PASSWORD && process.env.APP_AUTH_SECRET);
}

function getSupabase() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key);
}

function dateMinusDaysIso(days) {
  const ms = Math.max(0, Number(days) || 0) * 24 * 60 * 60 * 1000;
  return new Date(Date.now() - ms).toISOString();
}

function getApiKeys() {
  const keys = [];
  const k1 = process.env.VT_API_KEY;
  if (k1) keys.push(k1);
  for (let i = 2; i <= 10; i++) {
    const k = process.env[`VT_API_KEY_${i}`];
    if (k) keys.push(k);
  }
  return keys;
}

function httpsGet(url, headers) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch {
          reject(new Error('Failed to parse VT response: ' + body.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (authEnabled() && !requireAuth(req, res)) return;

  const apiKeys = getApiKeys();

  // ── Health check ──────────────────────────────
  if (req.query.health === '1') {
    return res.status(200).json({
      ok: true,
      totalKeys: apiKeys.length,
      keys: apiKeys.map((k, i) => ({ index: i + 1, prefix: k.slice(0, 6) + '...' })),
      node: process.version,
    });
  }

  // ── Validation ────────────────────────────────
  if (apiKeys.length === 0) {
    return res
      .status(500)
      .json({
        error: { message: 'No API keys configured. Set VT_API_KEY in environment variables.' },
      });
  }

  const { ioc: rawIoc } = req.query;
  if (!rawIoc) {
    return res.status(400).json({ error: { message: 'Missing ?ioc= param.' } });
  }

  // ── Clean + detect ────────────────────────────
  const ioc = extractIOC(rawIoc);
  const type = detectType(ioc);

  if (!type) {
    return res.status(400).json({
      error: {
        message: `Cannot detect IOC type for: "${ioc}". Supports IP, domain, hash (MD5/SHA-1/SHA-256/SHA-512).`,
      },
    });
  }

  const urlMap = {
    hash: `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
    ip: `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
    domain: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`,
  };

  const vtUrl = urlMap[type];

  // Detect rate limit in response body (some APIs return 403/200 with quota message)
  function isRateLimitResponse(status, data) {
    if (status === 429) return true;
    const msg = (data?.error?.message || data?.message || '').toLowerCase();
    if (status === 403 && /quota|rate limit|too many|limit exceeded/.test(msg)) return true;
    if (status === 200 && data?.error && /quota|rate limit|too many/.test(msg)) return true;
    return false;
  }

  // ── Try each key in order; on 429/quota auto-switch to next key for this same request ──
  let lastError = null;
  let rateLimitedCount = 0;

  for (let i = 0; i < apiKeys.length; i++) {
    try {
      const { status, data } = await httpsGet(vtUrl, {
        'x-apikey': apiKeys[i],
        Accept: 'application/json',
        'User-Agent': 'Charlie-kerennnn/1.0',
      });

      if (isRateLimitResponse(status, data)) {
        rateLimitedCount++;
        continue; // try next key immediately for this same IOC
      }

      // Inject meta so frontend knows cleaned IOC + type
      if (status === 200 && data.data) {
        data._meta = { type, ioc, original: rawIoc };
      }

      // Cache IP scans (Supabase) for "seen before" + recent list
      if (status === 200 && data.data && type === 'ip') {
        const supabase = getSupabase();
        if (supabase) {
          const ttlDays = 15;
          const cutoffIso = dateMinusDaysIso(ttlDays);
          try {
            // Lazy cleanup TTL
            await supabase.from('vt_ip_cache').delete().lt('last_scanned_at', cutoffIso);
          } catch {
            // ignore cleanup errors (do not block VT response)
          }

          let existing = null;
          try {
            const { data: row } = await supabase
              .from('vt_ip_cache')
              .select('id,ip,scan_count,last_scanned_at,first_scanned_at')
              .eq('ip', ioc)
              .maybeSingle();
            existing = row || null;
          } catch {
            existing = null;
          }

          const lastStats = data?.data?.attributes?.last_analysis_stats || {};
          const malicious = lastStats.malicious || 0;
          const suspicious = lastStats.suspicious || 0;
          const total = Object.values(lastStats).reduce((a, b) => a + b, 0);
          const vtVerdict =
            malicious > 3
              ? 'malicious'
              : malicious > 0 || suspicious > 3
                ? 'suspicious'
                : total === 0
                  ? 'unknown'
                  : 'clean';

          const cacheMeta = {
            enabled: true,
            ttlDays,
            seenBefore: !!existing,
            stableId: existing ? existing.id || null : null,
            scanCount: existing ? Number(existing.scan_count || 0) : 0,
            lastSeen: existing ? existing.last_scanned_at || null : null,
          };
          data._meta.cache = cacheMeta;

          // Upsert/insert cache row (best-effort)
          const nowIso = new Date().toISOString();
          const vtPayload = {
            reputation: data?.data?.attributes?.reputation,
            country: data?.data?.attributes?.country,
            asn: data?.data?.attributes?.asn,
            as_owner: data?.data?.attributes?.as_owner,
            network: data?.data?.attributes?.network,
            last_analysis_stats: lastStats,
          };
          const vtStats = { malicious, suspicious, total, undetected: lastStats.undetected || 0 };
          try {
            if (existing) {
              const nextCount = Number(existing.scan_count || 0) + 1;
              await supabase
                .from('vt_ip_cache')
                .update({
                  scan_count: nextCount,
                  last_scanned_at: nowIso,
                  vt_verdict: vtVerdict,
                  vt_stats: vtStats,
                  vt_payload: vtPayload,
                })
                .eq('ip', ioc);
              data._meta.cache.scanCount = nextCount;
              data._meta.cache.lastSeen = nowIso;
            } else {
              const { data: inserted } = await supabase
                .from('vt_ip_cache')
                .insert({
                ip: ioc,
                scan_count: 1,
                first_scanned_at: nowIso,
                last_scanned_at: nowIso,
                vt_verdict: vtVerdict,
                vt_stats: vtStats,
                vt_payload: vtPayload,
                })
                .select('id')
                .maybeSingle();
              data._meta.cache.scanCount = 1;
              data._meta.cache.lastSeen = nowIso;
              data._meta.cache.stableId = inserted ? inserted.id || null : null;
            }
          } catch {
            // ignore DB errors (do not block VT response)
          }
        } else {
          data._meta.cache = { enabled: false, reason: 'Supabase not configured' };
        }
      }

      if (status === 200) res.setHeader('X-VT-Key-Used', `key-${i + 1}-of-${apiKeys.length}`);
      return res.status(status).json(data);
    } catch (err) {
      lastError = err;
      continue;
    }
  }

  // All keys failed: distinguish rate limit vs access error
  if (rateLimitedCount === apiKeys.length) {
    return res.status(429).json({
      error: { message: `All ${apiKeys.length} API key(s) are rate limited. Try again later.` },
    });
  }

  // Cannot access VirusTotal (network, timeout, parse error, etc.)
  const msg = lastError?.message || 'Unknown error';
  return res.status(503).json({
    error: { message: `Cannot access VirusTotal: ${msg}` },
  });
};
