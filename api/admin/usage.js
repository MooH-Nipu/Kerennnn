'use strict';
const { requireRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const MAX_ROWS = 20000; // safety cap on rows pulled for in-memory aggregation
const ALLOWED_DAYS = [1, 7, 30, 90];

function inc(map, key, by = 1) {
  if (!key && key !== 0) return;
  map.set(key, (map.get(key) || 0) + by);
}
function mapToSorted(map, keyName) {
  return [...map.entries()]
    .map(([k, total]) => ({ [keyName]: k, total }))
    .sort((a, b) => b.total - a.total);
}

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
      .select('user_id, username, service, ioc_type, outcome, vt_key, created_at')
      .gte('created_at', cutoffIso)
      .order('created_at', { ascending: false })
      .limit(MAX_ROWS);
    if (error) return serverError(res, error, 'admin/usage');

    const rows = data ?? [];

    const byServiceMap = new Map();
    const byOutcomeMap = new Map();
    const byIocTypeMap = new Map();
    const byVtKeyMap = new Map();
    const byDayMap = new Map();
    const serviceSet = new Set();
    // username → { total, ok, rate_limited, error, services: Map }
    const userAgg = new Map();

    for (const r of rows) {
      const svc = r.service || 'Unknown';
      const outcome = r.outcome || 'ok';
      serviceSet.add(svc);
      inc(byServiceMap, svc);
      inc(byOutcomeMap, outcome);
      if (r.ioc_type) inc(byIocTypeMap, r.ioc_type);
      if (r.vt_key) inc(byVtKeyMap, r.vt_key);
      inc(byDayMap, String(r.created_at).slice(0, 10));

      const uname = r.username || '(unknown)';
      if (!userAgg.has(uname)) {
        userAgg.set(uname, { username: uname, total: 0, ok: 0, rate_limited: 0, error: 0, services: new Map() });
      }
      const u = userAgg.get(uname);
      u.total += 1;
      if (outcome === 'rate_limited') u.rate_limited += 1;
      else if (outcome === 'error') u.error += 1;
      else u.ok += 1;
      inc(u.services, svc);
    }

    const services = [...serviceSet].sort();

    // Per-user, per-service matrix for a stacked bar chart.
    const perUserService = [...userAgg.values()]
      .sort((a, b) => b.total - a.total)
      .map((u) => {
        const row = { username: u.username, total: u.total };
        for (const svc of services) row[svc] = u.services.get(svc) || 0;
        return row;
      });

    const byUser = [...userAgg.values()]
      .map((u) => ({ username: u.username, total: u.total, ok: u.ok, rate_limited: u.rate_limited, error: u.error }))
      .sort((a, b) => b.total - a.total);

    const byDay = [...byDayMap.entries()]
      .map(([day, total]) => ({ day, total }))
      .sort((a, b) => a.day.localeCompare(b.day));

    return res.status(200).json({
      ok: true,
      rangeDays: days,
      total: rows.length,
      capped: rows.length >= MAX_ROWS,
      services,
      byUser,
      perUserService,
      byService: mapToSorted(byServiceMap, 'service'),
      byOutcome: mapToSorted(byOutcomeMap, 'outcome'),
      byIocType: mapToSorted(byIocTypeMap, 'ioc_type'),
      byVtKey: mapToSorted(byVtKeyMap, 'vt_key'),
      byDay,
      recent: rows.slice(0, 100),
    });
  } catch (e) {
    return serverError(res, e, 'admin/usage');
  }
};
