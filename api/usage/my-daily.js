'use strict';
const { requireAuth } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

// Per-user daily usage summary for the IoC Scan tab quota indicator.
// Returns { ok, vtToday, vtDailyLimit } — VT daily limit is 500 (free tier).
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(200).json({ ok: true, vtToday: 0, vtDailyLimit: 500 });
  }

  try {
    const today = new Date().toISOString().slice(0, 10);
    const { count, error } = await supabase
      .from('api_usage')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', req.auth?.userId)
      .eq('service', 'VirusTotal')
      .gte('created_at', today);

    if (error) return serverError(res, error, 'usage/my-daily');

    return res.status(200).json({
      ok: true,
      vtToday: count ?? 0,
      vtDailyLimit: 500,
    });
  } catch (e) {
    return serverError(res, e, 'usage/my-daily');
  }
};
