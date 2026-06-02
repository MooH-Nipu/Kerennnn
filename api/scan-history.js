'use strict';
const { requireAuth, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

// Strictly per-user history: every query is filtered by req.auth.userId.
const MAX_ROWS = 50;      // hard cap per user; oldest rows pruned on each insert
const DEFAULT_LIMIT = MAX_ROWS;
const MAX_LIMIT = 200;

function clampLimit(raw) {
  const n = parseInt(String(raw ?? ''), 10);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_LIMIT;
  return Math.min(MAX_LIMIT, n);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
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
    const limit = clampLimit(req.query?.limit);
    const { data, error } = await supabase
      .from('scan_history')
      .select('id, input, count, items, created_at')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) return serverError(res, error, 'scan-history GET');
    return res.status(200).json({ ok: true, entries: data ?? [] });
  }

  if (req.method === 'POST') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const input = String(body?.input ?? '').trim();
    if (!input) return res.status(400).json({ error: 'Missing input.' });

    const items = Array.isArray(body?.items) ? body.items : [];
    const count = Number.isFinite(body?.count) ? Math.max(0, Math.floor(body.count)) : items.length;

    const { data, error } = await supabase
      .from('scan_history')
      .insert({
        user_id:  userId,
        username: req.auth.username ?? null,
        input,
        count,
        items,
      })
      .select('id, input, count, items, created_at')
      .single();

    if (error) return serverError(res, error, 'scan-history POST');

    // Best-effort prune: keep only the MAX_ROWS newest rows for this user.
    // Errors here are silently swallowed — the insert already succeeded.
    try {
      const { data: overflow } = await supabase
        .from('scan_history')
        .select('id')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .range(MAX_ROWS, MAX_ROWS + 499);
      if (overflow && overflow.length > 0) {
        await supabase.from('scan_history').delete().in('id', overflow.map(r => r.id));
      }
    } catch { /* prune failure is non-fatal */ }

    return res.status(201).json({ ok: true, entry: data });
  }

  if (req.method === 'DELETE') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    // Clear all of the current user's history.
    if (body?.clear === true) {
      const { error } = await supabase.from('scan_history').delete().eq('user_id', userId);
      if (error) return serverError(res, error, 'scan-history DELETE all');
      return res.status(200).json({ ok: true });
    }

    const id = body?.id;
    if (!id) return res.status(400).json({ error: 'Missing id (or pass { clear: true }).' });

    // Ownership enforced server-side: the user_id filter means a user can only
    // delete their own rows even if they guess another entry's id.
    const { error } = await supabase
      .from('scan_history')
      .delete()
      .eq('id', id)
      .eq('user_id', userId);

    if (error) return serverError(res, error, 'scan-history DELETE');
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};

// Exposed for unit tests (the handler is the default export above).
module.exports.clampLimit = clampLimit;
