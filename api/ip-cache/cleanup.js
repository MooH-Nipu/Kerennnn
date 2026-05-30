const { createClient } = require('@supabase/supabase-js');
const { requireRole } = require('../_auth');

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
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  // Destructive maintenance — restrict to admins.
  if (!requireRole(req, res, ['admin'])) return;

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const ttlDays = clampInt(req.query?.days, 1, 365, 15);
  const cutoffIso = dateMinusDaysIso(ttlDays);
  const { error } = await supabase.from('vt_ip_cache').delete().lt('first_scanned_at', cutoffIso);
  if (error) return res.status(500).json({ error: error.message || String(error) });
  return res.status(200).json({ ok: true, ttlDays });
};

