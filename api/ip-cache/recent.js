const { createClient } = require('@supabase/supabase-js');
const { requireAuth } = require('../_auth');

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

function clampInt(n, lo, hi, fallback) {
  const x = Number.parseInt(String(n), 10);
  if (!Number.isFinite(x)) return fallback;
  return Math.max(lo, Math.min(hi, x));
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  if (authEnabled() && !requireAuth(req, res)) return;

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const limit = clampInt(req.query?.limit, 1, 50, 15);
  const ttlDays = 15;
  const cutoffIso = dateMinusDaysIso(ttlDays);

  // Lazy cleanup TTL (best-effort)
  try {
    await supabase.from('vt_ip_cache').delete().lt('last_scanned_at', cutoffIso);
  } catch {
    // ignore cleanup errors
  }

  const { data, error } = await supabase
    .from('vt_ip_cache')
    .select('ip,scan_count,first_scanned_at,last_scanned_at,vt_verdict,vt_stats')
    .order('last_scanned_at', { ascending: false })
    .limit(limit);

  if (error) return res.status(500).json({ error: error.message || String(error) });
  return res.status(200).json({ ok: true, ttlDays, items: data || [] });
};

