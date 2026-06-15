'use strict';
const { requireRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const PRESET_DAYS = [1, 7, 30, 90];

/** Auto-select the TI usage-over-time bucket granularity from the day range. */
function pickBucket(days) {
  if (days <= 1) return '30m';   // 24h  → 30-minute buckets
  if (days <= 30) return '1d';   // 7d, 30d → daily buckets
  return '1w';                   // 90d+ → weekly buckets
}

// Admin API-usage aggregation for the "API Usage" tab. Calls a Postgres
// function (supabase/api_usage_aggregation.sql) that does all GROUP BY
// aggregation server-side — single round-trip, O(1) Vercel memory.
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
  if (!Number.isFinite(days) || days < 1) days = 7;
  days = Math.min(days, 365);

  const bucket = pickBucket(days);

  try {
    const { data, error } = await supabase.rpc('get_api_usage_stats', {
      days_param: days,
      bucket_param: bucket,
    });

    if (error) {
      // If the function hasn't been created in Supabase yet, fall back to a
      // helpful error instead of the raw Postgres "function not found" message.
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
      rangeDays: days,
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
