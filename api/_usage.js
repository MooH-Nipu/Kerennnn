'use strict';
const { getSupabase } = require('./_supabase');

/**
 * Best-effort per-user API usage logging. Never throws — telemetry must not
 * block or fail the primary request. Writes to public.api_usage.
 *
 * @param {object} req   the request (reads req.auth.userId / req.auth.username)
 * @param {object|object[]} rows  one or many { service, ioc_type?, outcome?, vt_key? }
 */
async function logApiUsage(req, rows) {
  const list = (Array.isArray(rows) ? rows : [rows]).filter(Boolean);
  if (!list.length) return;
  const supabase = getSupabase();
  if (!supabase) return;
  const auth = (req && req.auth) || {};
  try {
    await supabase.from('api_usage').insert(
      list.map((r) => ({
        user_id: auth.userId || null,
        username: auth.username || null,
        service: r.service,
        ioc_type: r.ioc_type || null,
        outcome: r.outcome || 'ok',
        vt_key: r.vt_key || null,
      }))
    );
  } catch {
    /* best-effort: swallow telemetry failures */
  }
}

module.exports = { logApiUsage };
