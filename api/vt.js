const { extractIOC, detectType } = require('./_ioc');
const { getSupabase } = require('./_supabase');
const { getVtKeys, getVtKeysForRequest, markVtKeyRateLimited, shouldTryNextVtKey, isVtRateLimited, isVtBadKey } = require('./_vtkeys');
const { httpGet } = require('./_http');
const { requireAuth } = require('./_auth');
const { logApiUsage } = require('./_usage');

function dateMinusDaysIso(days) {
  const ms = Math.max(0, Number(days) || 0) * 24 * 60 * 60 * 1000;
  return new Date(Date.now() - ms).toISOString();
}

// Curated VT attribute subset persisted per IOC type for the deep-analysis page
// (vt_ioc_cache.vt_payload). Stored flat (no nesting) — ResultPage reads it directly.
function buildVtCachePayload(type, attrs) {
  const a = attrs || {};
  if (type === 'domain') {
    return {
      last_analysis_stats: a.last_analysis_stats || {},
      reputation: a.reputation,
      registrar: a.registrar,
      creation_date: a.creation_date,
      last_update_date: a.last_update_date,
      categories: a.categories,
    };
  }
  if (type === 'hash') {
    return {
      last_analysis_stats: a.last_analysis_stats || {},
      reputation: a.reputation,
      names: Array.isArray(a.names) ? a.names.slice(0, 5) : undefined,
      type_description: a.type_description,
      magic: a.magic,
      size: a.size,
      first_submission_date: a.first_submission_date,
      last_analysis_date: a.last_analysis_date,
    };
  }
  return a;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Auth required: this endpoint spends the server's paid VirusTotal keys.
  if (!requireAuth(req, res)) return;

  const apiKeys = getVtKeysForRequest();

  // ── Health check ──────────────────────────────
  if (req.query.health === '1') {
    const allKeys = getVtKeys();
    return res.status(200).json({
      ok: true,
      totalKeys: allKeys.length,
      keys: allKeys.map((k, i) => ({ index: i + 1, prefix: k.slice(0, 6) + '...' })),
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

  // For IPs: short-circuit from DB cache — skip VT API call entirely
  if (type === 'ip') {
    const supabase = getSupabase();
    if (supabase) {
      try {
        const cutoffIso = dateMinusDaysIso(15);
        const { data: cached } = await supabase
          .from('vt_ip_cache')
          .select('id,ip,vt_payload,vt_stats,vt_verdict,scan_count,first_scanned_at,last_scanned_at,corr_payload,corr_confidence')
          .eq('ip', ioc)
          .gt('first_scanned_at', cutoffIso)
          .maybeSingle();

        if (cached && cached.vt_payload) {
          return res.status(200).json({
            data: { attributes: cached.vt_payload },
            _meta: {
              type: 'ip',
              ioc,
              original: rawIoc,
              cache: {
                enabled: true,
                seenBefore: true,
                stableId: cached.id || null,
                scanCount: cached.scan_count || 0,
                lastSeen: cached.last_scanned_at,
                fromCache: true,
                corrPayload: cached.corr_payload && Array.isArray(cached.corr_payload.sources) && cached.corr_payload.sources.length > 0
                  && cached.corr_payload.sources.some(s => s.source === 'Enrichment')
                  ? cached.corr_payload
                  : null,
              },
            },
          });
        }
      } catch {
        // DB error — fall through to VT API
      }
    }
  }

  const urlMap = {
    hash: `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
    ip: `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
    domain: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`,
  };

  const vtUrl = urlMap[type];

  // ── Try each key; on quota/rate-limit or bad key, auto-switch to next for this IOC ──
  let lastError = null;
  let rateLimitedCount = 0;
  let badKeyCount = 0;
  const keyAttempts = []; // debug: track what each key returned

  for (let i = 0; i < apiKeys.length; i++) {
    const keyPrefix = apiKeys[i].slice(0, 8) + '…';
    try {
      const { status, data } = await httpGet(
        vtUrl,
        {
          'x-apikey': apiKeys[i],
          Accept: 'application/json',
          'User-Agent': 'Charlie-kerennnn/1.0',
        },
        { timeout: 10000 }
      );

      if (shouldTryNextVtKey(status, data)) {
        if (isVtRateLimited(status, data)) {
          rateLimitedCount++;
          markVtKeyRateLimited(apiKeys[i]);
          keyAttempts.push({ key: keyPrefix, status, result: 'rate_limited' });
        } else if (isVtBadKey(status, data)) {
          badKeyCount++;
          keyAttempts.push({ key: keyPrefix, status, result: 'bad_key' });
        }
        continue;
      }
      keyAttempts.push({ key: keyPrefix, status, result: 'ok' });

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
            await supabase.from('vt_ip_cache').delete().lt('first_scanned_at', cutoffIso);
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

          // Insert new IP only (best-effort); repeat lookups do not refresh this row
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
            if (!existing) {
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

      // Cache domain/hash scans (Supabase) so the "Analisa Mendalam" deep-analysis
      // page + seen-before badge work. Insert-only (no read short-circuit) so live
      // detection stats stay fresh; the cached row is a point-in-time snapshot.
      if (status === 200 && data.data && (type === 'domain' || type === 'hash')) {
        const supabase = getSupabase();
        if (supabase) {
          const ttlDays = 15;
          const cutoffIso = dateMinusDaysIso(ttlDays);
          try {
            await supabase.from('vt_ioc_cache').delete().lt('first_scanned_at', cutoffIso);
          } catch {
            // ignore cleanup errors (do not block VT response)
          }

          let existing = null;
          try {
            const { data: row } = await supabase
              .from('vt_ioc_cache')
              .select('id,scan_count,last_scanned_at,first_scanned_at')
              .eq('ioc_type', type)
              .eq('ioc', ioc)
              .maybeSingle();
            existing = row || null;
          } catch {
            existing = null;
          }

          const attrs = data?.data?.attributes || {};
          const lastStats = attrs.last_analysis_stats || {};
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

          data._meta.cache = {
            enabled: true,
            ttlDays,
            seenBefore: !!existing,
            stableId: existing ? existing.id || null : null,
            scanCount: existing ? Number(existing.scan_count || 0) : 0,
            lastSeen: existing ? existing.last_scanned_at || null : null,
          };

          const nowIso = new Date().toISOString();
          const vtStats = { malicious, suspicious, total, undetected: lastStats.undetected || 0 };
          try {
            if (!existing) {
              const { data: inserted } = await supabase
                .from('vt_ioc_cache')
                .insert({
                  ioc,
                  ioc_type: type,
                  scan_count: 1,
                  first_scanned_at: nowIso,
                  last_scanned_at: nowIso,
                  vt_verdict: vtVerdict,
                  vt_stats: vtStats,
                  vt_payload: buildVtCachePayload(type, attrs),
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
      logApiUsage(req, {
        service: 'VirusTotal',
        ioc_type: type,
        outcome: status === 200 ? 'ok' : 'error',
        vt_key: keyPrefix,
      }).catch(() => {});
      return res.status(status).json(data);
    } catch (err) {
      keyAttempts.push({ key: keyPrefix, status: null, result: 'network_error', error: err?.message });
      lastError = err;
      continue;
    }
  }

  // All keys failed: distinguish rate limit vs invalid keys vs access error
  if (badKeyCount === apiKeys.length) {
    logApiUsage(req, { service: 'VirusTotal', ioc_type: type, outcome: 'error' }).catch(() => {});
    return res.status(401).json({
      error: {
        message: `All ${apiKeys.length} configured API key(s) are invalid or inactive. Check VT_API_KEY env vars.`,
      },
      _debug: { keyAttempts },
    });
  }

  if (rateLimitedCount === apiKeys.length) {
    logApiUsage(req, { service: 'VirusTotal', ioc_type: type, outcome: 'rate_limited' }).catch(() => {});
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: {
        message: `All ${apiKeys.length} unique API key(s) hit VirusTotal rate limits (per-minute: 4 req/min per key).`,
      },
      _debug: { keyAttempts },
    });
  }

  // Cannot access VirusTotal (network, timeout, parse error, etc.)
  const msg = lastError?.message || 'Unknown error';
  logApiUsage(req, { service: 'VirusTotal', ioc_type: type, outcome: 'error' }).catch(() => {});
  return res.status(503).json({
    error: { message: `Cannot access VirusTotal: ${msg}` },
    _debug: { keyAttempts },
  });
};
