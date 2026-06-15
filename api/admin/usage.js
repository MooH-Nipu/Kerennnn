'use strict';
const { requireRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const ALLOWED_DAYS = [1, 7, 30, 90];

/** Auto-select the TI usage-over-time bucket from the range duration in hours. */
function pickBucket(from, to) {
  const hours = (to - from) / (1000 * 60 * 60);
  if (hours <= 36) return '30m';     // ≤1.5 days → 30-minute buckets
  if (hours <= 24 * 45) return '1d'; // ≤45 days → daily buckets
  return '1w';                       // >45 days → weekly buckets
}

// Admin API-usage aggregation. Accepts ?from=ISO&to=ISO for an arbitrary
// time window (Elastic-style), or falls back to ?days=N for presets.
// Calls a Postgres function that does all GROUP BY server-side.
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

  // Parse time window: prefer explicit ?from=&to=ISO, fall back to ?days=N.
  let from, to;
  const fromRaw = String(req.query?.from ?? '').trim();
  const toRaw   = String(req.query?.to   ?? '').trim();

  if (fromRaw && toRaw) {
    from = new Date(fromRaw);
    to   = new Date(toRaw);
    if (isNaN(from.getTime()) || isNaN(to.getTime())) {
      return res.status(400).json({ error: 'Invalid from/to date. Use ISO 8601 format.' });
    }
    if (from >= to) return res.status(400).json({ error: 'from must be before to.' });
  } else {
    let days = parseInt(String(req.query?.days ?? ''), 10);
    if (!ALLOWED_DAYS.includes(days)) days = 7;
    to   = new Date();
    from = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  }

  const bucket = pickBucket(from, to);

  try {
    const { data, error } = await supabase.rpc('get_api_usage_stats', {
      from_ts: from.toISOString(),
      to_ts: to.toISOString(),
      bucket_param: bucket,
    });

    if (error) {
      if (error.code === '42883' || error.message?.includes('function') || error.message?.includes('not found')) {
        return res.status(503).json({
          error: 'Aggregation function not deployed. Run supabase/api_usage_aggregation.sql in the Supabase SQL Editor.',
        });
      }
      return serverError(res, error, 'admin/usage');
    }

    if (!data) {
      return serverError(res, new Error('No result from get_api_usage_stats'), 'admin/usage');
    }

    return res.status(200).json({
      ok: true,
      from: from.toISOString(),
      to: to.toISOString(),
      bucket,
      total: data.total ?? 0,
      capped: false,
      byUser: data.byUser ?? [],
      byOutcome: data.byOutcome ?? [],
      byDay: data.byDay ?? [],
      recent: data.recent ?? [],
    });
  } catch (e) {
    return serverError(res, e, 'admin/usage');
  }
};
