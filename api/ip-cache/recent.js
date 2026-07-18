const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

function dateMinusDaysIso(days) {
  const ms = Math.max(0, Number(days) || 0) * 24 * 60 * 60 * 1000;
  return new Date(Date.now() - ms).toISOString();
}

function clampInt(n, lo, hi, fallback) {
  const x = Number.parseInt(String(n), 10);
  if (!Number.isFinite(x)) return fallback;
  return Math.max(lo, Math.min(hi, x));
}

function parseDate(value) {
  const date = new Date(String(value || ''));
  return Number.isNaN(date.getTime()) ? null : date;
}

function pickBucket(from, to) {
  const hours = (to.getTime() - from.getTime()) / (1000 * 60 * 60);
  if (hours <= 36) return '30m';
  if (hours <= 24 * 45) return '1d';
  return '1w';
}

function bucketStart(date, bucket) {
  const result = new Date(date);
  if (bucket === '30m') {
    result.setMinutes(result.getMinutes() < 30 ? 0 : 30, 0, 0);
    return result;
  }
  if (bucket === '1w') {
    const day = (result.getDay() + 6) % 7;
    result.setDate(result.getDate() - day);
  }
  result.setHours(0, 0, 0, 0);
  return result;
}

function formatBucket(date, bucket) {
  const pad = (value) => String(value).padStart(2, '0');
  const day = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  return bucket === '30m' ? `${day} ${pad(date.getHours())}:${pad(date.getMinutes())}` : day;
}

function buildScanTimeline(rows, from, to) {
  const bucket = pickBucket(from, to);
  const counts = new Map();
  for (const row of rows) {
    const key = formatBucket(bucketStart(new Date(row.first_scanned_at), bucket), bucket);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return {
    bucket,
    points: [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([time, scans]) => ({ time, scans })),
  };
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const limit = clampInt(req.query?.limit, 1, 50, 15);
  const ttlDays = 15;
  const cutoffIso = dateMinusDaysIso(ttlDays);
  const from = parseDate(req.query?.from);
  const to = parseDate(req.query?.to);
  if ((req.query?.from && !from) || (req.query?.to && !to) || (from && to && from >= to)) {
    return res.status(400).json({ error: 'Invalid scan timeline range.' });
  }

  // Lazy cleanup TTL (best-effort)
  try {
    await supabase.from('vt_ip_cache').delete().lt('first_scanned_at', cutoffIso);
  } catch {
    // ignore cleanup errors
  }

  const { data, error } = await supabase
    .from('vt_ip_cache')
    .select('id,ip,scan_count,first_scanned_at,last_scanned_at,vt_verdict,vt_stats,corr_confidence')
    .order('last_scanned_at', { ascending: false })
    .limit(limit);

  if (error) return serverError(res, error, 'ip-cache recent');

  // Get total count + verdict breakdown (not limited by fetch).
  const timelineQuery = supabase.from('vt_ip_cache').select('first_scanned_at');
  if (from) timelineQuery.gte('first_scanned_at', from.toISOString());
  if (to) timelineQuery.lt('first_scanned_at', to.toISOString());

  const [totalRes, malRes, susRes, cleanRes, timelineRes] = await Promise.all([
    supabase.from('vt_ip_cache').select('id', { count: 'exact', head: true }),
    supabase.from('vt_ip_cache').select('id', { count: 'exact', head: true }).eq('vt_verdict', 'malicious'),
    supabase.from('vt_ip_cache').select('id', { count: 'exact', head: true }).eq('vt_verdict', 'suspicious'),
    supabase.from('vt_ip_cache').select('id', { count: 'exact', head: true }).eq('vt_verdict', 'clean'),
    timelineQuery,
  ]);
  if (timelineRes.error) return serverError(res, timelineRes.error, 'ip-cache scan timeline');

  const scanTimeline = from && to
    ? buildScanTimeline(timelineRes.data || [], from, to)
    : { bucket: null, points: [] };

  return res.status(200).json({
    ok: true, ttlDays,
    total: totalRes.count ?? (data || []).length,
    malicious: malRes.count ?? 0,
    suspicious: susRes.count ?? 0,
    clean: cleanRes.count ?? 0,
    items: data || [],
    scanTimeline,
  });
};

