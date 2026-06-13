'use strict';
const { getSupabase } = require('./_supabase');

/**
 * Best-effort per-user API usage logging. Never throws — telemetry must not
 * block or fail the primary request. Writes to public.api_usage.
 *
 * @param {object} req   the request (reads req.auth.userId / req.auth.username)
 * @param {object|object[]} rows  one or many { service, ioc_type?, outcome?, api_key? }
 *   `api_key` is a short, non-secret PREFIX of whichever TI key served the call
 *   (any source, not just VirusTotal) — used for the admin usage breakdown.
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
        api_key: r.api_key || null,
      }))
    );
  } catch {
    /* best-effort: swallow telemetry failures */
  }
}

module.exports = { logApiUsage };
