'use strict';
const { requireRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const MAX_ROWS = 20000; // safety cap on rows pulled for in-memory aggregation
const ALLOWED_DAYS = [1, 7, 30, 90];

// Admin API-usage aggregation for the "API Usage" tab. Pulls recent rows within
// the window and aggregates in memory (the supabase-js client has no group-by).
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireRole(req, res, ['admin', 'l2'])) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  let days = parseInt(String(req.query?.days ?? ''), 10);
  if (!ALLOWED_DAYS.includes(days)) days = 7;
  const cutoffIso = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  try {
    const { data, error } = await supabase
      .from('api_usage')
      .select('username, service, ioc_type, outcome, api_key, created_at')
      .gte('created_at', cutoffIso)
      .order('created_at', { ascending: false })
      .limit(MAX_ROWS);
    if (error) return serverError(res, error, 'admin/usage');

    const rows = data ?? [];

    const byOutcomeMap = new Map(); // outcome → count (for the summary stat cards)
    const vtByDayMap = new Map();   // YYYY-MM-DD → VirusTotal call count
    // username → { total, ok, rate_limited, error }
    const userAgg = new Map();

    for (const r of rows) {
      const outcome = r.outcome || 'ok';
      byOutcomeMap.set(outcome, (byOutcomeMap.get(outcome) || 0) + 1);

      if (r.service === 'VirusTotal') {
        const day = String(r.created_at).slice(0, 10);
        vtByDayMap.set(day, (vtByDayMap.get(day) || 0) + 1);
      }

      const uname = r.username || '(unknown)';
      if (!userAgg.has(uname)) {
        userAgg.set(uname, { username: uname, total: 0, ok: 0, rate_limited: 0, error: 0 });
      }
      const u = userAgg.get(uname);
      u.total += 1;
      if (outcome === 'rate_limited') u.rate_limited += 1;
      else if (outcome === 'error') u.error += 1;
      else u.ok += 1;
    }

    // All TI combined per user (no per-service split): one total + outcome counts.
    const byUser = [...userAgg.values()].sort((a, b) => b.total - a.total);

    const byOutcome = [...byOutcomeMap.entries()]
      .map(([outcome, total]) => ({ outcome, total }))
      .sort((a, b) => b.total - a.total);

    // Total VirusTotal calls per day across the selected timeframe.
    const vtByDay = [...vtByDayMap.entries()]
      .map(([day, total]) => ({ day, total }))
      .sort((a, b) => a.day.localeCompare(b.day));

    return res.status(200).json({
      ok: true,
      rangeDays: days,
      total: rows.length,
      capped: rows.length >= MAX_ROWS,
      byUser,
      byOutcome,
      vtByDay,
      recent: rows.slice(0, 10),
    });
  } catch (e) {
    return serverError(res, e, 'admin/usage');
  }
};
