'use strict';
const { requireAuth, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

const PAGE_SIZE = 20;

/**
 * Strip PostgREST filter-control characters so a user search term cannot break
 * out of the ilike predicate and inject additional filter logic.
 * Reserved: , ( ) \ separate/group conditions; * % are like-wildcards.
 */
function sanitizeSearchTerm(q) {
  return String(q ?? '').trim().replace(/[,()\\*%]/g, '');
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  if (req.method === 'GET') {
    const q      = String(req.query?.q ?? '').trim();
    const offset = Math.max(0, parseInt(String(req.query?.offset ?? '0'), 10) || 0);

    let query = supabase
      .from('ir_cases')
      .select('id, title, created_by, created_at, updated_at', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + PAGE_SIZE - 1);

    if (q) {
      const safeQ = sanitizeSearchTerm(q);
      if (safeQ) {
        query = query.or(`title.ilike.%${safeQ}%,description.ilike.%${safeQ}%`);
      }
    }

    const { data, error, count } = await query;
    if (error) return serverError(res, error, 'ir-cases GET');
    return res.status(200).json({ ok: true, cases: data ?? [], total: count ?? 0 });
  }

  if (req.method === 'POST') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const rawRows = Array.isArray(body) ? body : [body];
    if (!rawRows.length) return res.status(400).json({ error: 'Empty payload.' });

    const toInsert = [];
    for (const r of rawRows) {
      const title = String(r.title ?? '').trim();
      if (!title) return res.status(400).json({ error: 'Missing title.' });
      toInsert.push({
        title,
        description: String(r.description ?? '').trim(),
        created_by:  req.auth.username,
      });
    }

    const { data, error } = await supabase
      .from('ir_cases')
      .insert(toInsert)
      .select('id, title, created_by, created_at, updated_at');

    if (error) return serverError(res, error, 'ir-cases');
    return res.status(201).json({ ok: true, cases: data });
  }

  if (req.method === 'PATCH') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const { id, title, description } = body ?? {};
    if (!id)                  return res.status(400).json({ error: 'Missing id.' });
    if (!String(title ?? '').trim()) return res.status(400).json({ error: 'Missing title.' });

    const { data, error } = await supabase
      .from('ir_cases')
      .update({
        title:       String(title).trim(),
        description: String(description ?? '').trim(),
        updated_at:  new Date().toISOString(),
      })
      .eq('id', id)
      .select('id, title, created_by, created_at, updated_at')
      .single();

    if (error) return serverError(res, error, 'ir-cases');
    if (!data)  return res.status(404).json({ error: 'Case not found.' });
    return res.status(200).json({ ok: true, case: data });
  }

  if (req.method === 'DELETE') {
    // Deleting cases is gated to non-L1 roles (mirrors the UI gate in IrManagerTab).
    if (req.auth.role === 'l1') {
      return res.status(403).json({ error: 'Forbidden: your role cannot delete cases.' });
    }

    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const { id } = body ?? {};
    if (!id) return res.status(400).json({ error: 'Missing id.' });

    const { error } = await supabase.from('ir_cases').delete().eq('id', id);
    if (error) return serverError(res, error, 'ir-cases');
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};

// Exposed for unit tests (the handler is the default export above).
module.exports.sanitizeSearchTerm = sanitizeSearchTerm;
