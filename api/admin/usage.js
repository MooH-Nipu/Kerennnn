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

    // Services that are separate analyst tools (not IoC-scan TI calls) — excluded
    // from per-user counts and the TI usage-over-time chart.
    const NON_TI_SERVICES = new Set(['ATT&CK', 'NVD']);

    const byOutcomeMap = new Map(); // outcome → count (for the summary stat cards)
    // day → service → count  (per-service per-day for the TI usage over time chart)
    const byDayMap = new Map();
    // username → { total, ok, rate_limited, error }
    const userAgg = new Map();

    for (const r of rows) {
      const outcome = r.outcome || 'ok';
      byOutcomeMap.set(outcome, (byOutcomeMap.get(outcome) || 0) + 1);

      // Per-service per-day counts for ALL services except ATT&CK/NVD.
      if (!NON_TI_SERVICES.has(r.service)) {
        const day = String(r.created_at).slice(0, 10);
        if (!byDayMap.has(day)) byDayMap.set(day, new Map());
        const svcMap = byDayMap.get(day);
        svcMap.set(r.service, (svcMap.get(r.service) || 0) + 1);
      }

      // Per-user counts: skip ATT&CK and NVD (separate analyst tools, not IoC scan).
      if (NON_TI_SERVICES.has(r.service)) continue;

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

    // Per-service per-day TI usage (all services except ATT&CK/NVD).
    // Collect all unique service names first so every day object has the same keys.
    const allServices = new Set();
    for (const svcMap of byDayMap.values()) {
      for (const svc of svcMap.keys()) allServices.add(svc);
    }
    const byDay = [...byDayMap.entries()]
      .map(([day, svcMap]) => {
        const entry = { day };
        for (const svc of allServices) entry[svc] = svcMap.get(svc) || 0;
        return entry;
      })
      .sort((a, b) => a.day.localeCompare(b.day));

    return res.status(200).json({
      ok: true,
      rangeDays: days,
      total: rows.length,
      capped: rows.length >= MAX_ROWS,
      byUser,
      byOutcome,
      byDay,
      recent: rows.slice(0, 10),
    });
  } catch (e) {
    return serverError(res, e, 'admin/usage');
  }
};
