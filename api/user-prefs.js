'use strict';
const { requireAuth, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

// Per-user UI preferences (currently the customizable tab bar). Strictly
// per-user: every read/write is filtered by req.auth.userId. One row per user.

// Mirror of TabId in src/lib/permissions.ts — keep in sync. Used to reject
// unknown ids so a client cannot stuff arbitrary strings into the prefs row.
const KNOWN_TABS = [
  'formatter', 'json', 'merger', 'ioc-scan', 'history',
  'pac-filter', 'daily-eod', 'admin-users', 'admin-logs', 'ir-manager',
];

function sanitizeIds(arr) {
  if (!Array.isArray(arr)) return [];
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    if (typeof x === 'string' && KNOWN_TABS.includes(x) && !seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const userId = req.auth.userId;

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('user_prefs')
      .select('tab_order, hidden_tabs')
      .eq('user_id', userId)
      .maybeSingle();

    if (error) return serverError(res, error, 'user-prefs GET');
    return res.status(200).json({
      ok: true,
      tab_order: data?.tab_order ?? [],
      hidden_tabs: data?.hidden_tabs ?? [],
    });
  }

  if (req.method === 'PUT') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const tab_order = sanitizeIds(body?.tab_order);
    const hidden_tabs = sanitizeIds(body?.hidden_tabs);

    const { data, error } = await supabase
      .from('user_prefs')
      .upsert(
        { user_id: userId, tab_order, hidden_tabs, updated_at: new Date().toISOString() },
        { onConflict: 'user_id' }
      )
      .select('tab_order, hidden_tabs')
      .single();

    if (error) return serverError(res, error, 'user-prefs PUT');
    return res.status(200).json({ ok: true, tab_order: data.tab_order, hidden_tabs: data.hidden_tabs });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};

// Exposed for unit tests (the handler is the default export above).
module.exports.sanitizeIds = sanitizeIds;
