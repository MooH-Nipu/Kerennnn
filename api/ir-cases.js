'use strict';
const { requireCurrentRole, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

const PAGE_SIZE = 20;
const ROLES = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];
const isManager = auth => ['admin', 'soc_lead'].includes(auth.role);

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
  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }
  if (!await requireCurrentRole(req, res, supabase, ROLES)) return;
  const deployEnv = process.env.KERENNNN_DEPLOY_ENV;
  if (deployEnv !== 'prod' && deployEnv !== 'dev') return res.status(503).json({ error: 'Deployment environment is not configured.' });

  if (req.method === 'GET') {
    const q      = String(req.query?.q ?? '').trim();
    const offset = Math.max(0, parseInt(String(req.query?.offset ?? '0'), 10) || 0);

    let query = supabase
      .from('ir_cases')
      .select('id, title, created_by, created_at, updated_at', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + PAGE_SIZE - 1);

    query = query.select(`id, title, created_by, created_at, updated_at, ir_case_dev_scope!${deployEnv === 'dev' ? 'inner' : 'left'}(case_id)`, { count: 'exact' });
    if (deployEnv === 'prod') query = query.is('ir_case_dev_scope', null);
    if (!isManager(req.auth)) query = query.eq('created_by', req.auth.username);
    if (q) {
      const safeQ = sanitizeSearchTerm(q);
      if (safeQ) {
        query = query.or(`title.ilike.%${safeQ}%,description.ilike.%${safeQ}%`);
      }
    }

    const { data, error, count } = await query;
    if (error) return serverError(res, error, 'ir-cases GET');
    return res.status(200).json({ ok: true, deployEnv, cases: (data ?? []).map(row => ({ id: row.id, title: row.title, created_by: row.created_by, created_at: row.created_at, updated_at: row.updated_at })), total: count ?? 0 });
  }

  if (req.method === 'POST') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const rawRows = Array.isArray(body) ? body : [body];
    if (!rawRows.length) return res.status(400).json({ error: 'Empty payload.' });

    const toInsert = [];
    if (rawRows.length > 100) return res.status(400).json({ error: 'Too many cases.' });
    for (const r of rawRows) {
      if (!r || typeof r !== 'object' || Array.isArray(r) || typeof r.title !== 'string' || r.title.trim().length > 500 || (r.description !== undefined && (typeof r.description !== 'string' || r.description.length > 100000))) return res.status(400).json({ error: 'Invalid case.' });

      const title = String(r.title ?? '').trim();
      if (!title) return res.status(400).json({ error: 'Missing title.' });
      toInsert.push({
        title,
        description: String(r.description ?? '').trim(),
        created_by:  req.auth.username,
      });
    }

    const { data, error } = deployEnv === 'dev'
      ? await supabase.rpc('ir_create_dev_cases', { p_cases: toInsert, p_creator_id: req.auth.userId })
      : await supabase.from('ir_cases').insert(toInsert).select('id, title, created_by, created_at, updated_at');

    if (error) return serverError(res, error, 'ir-cases');
    return res.status(201).json({ ok: true, cases: data });
  }

  if (req.method === 'PATCH') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

    const { id, title, description } = body ?? {};
    if (!id)                  return res.status(400).json({ error: 'Missing id.' });
    if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/i.test(id) || typeof title !== 'string' || title.length > 500 || (description !== undefined && (typeof description !== 'string' || description.length > 100000))) return res.status(400).json({ error: 'Invalid case.' });
    if (!String(title ?? '').trim()) return res.status(400).json({ error: 'Missing title.' });

    if (deployEnv === 'dev') {
      const { data, error } = await supabase.rpc('ir_update_dev_case', {
        p_case_id: id, p_title: title.trim(), p_description: String(description ?? '').trim(),
        p_creator_id: isManager(req.auth) ? null : req.auth.userId,
      });
      if (error) return serverError(res, error, 'ir-cases');
      if (!data) return res.status(404).json({ error: 'Case not found.' });
      return res.status(200).json({ ok: true, case: data });
    }
    if (deployEnv === 'prod') {
      const { data: scope, error: scopeError } = await supabase.from('ir_case_dev_scope').select('case_id').eq('case_id', id).maybeSingle();
      if (scopeError) return serverError(res, scopeError, 'ir-cases scope');
      if (scope) return res.status(404).json({ error: 'Case not found.' });
    }
    let updateQuery = supabase
      .from('ir_cases')
      .update({
        title:       String(title).trim(),
        description: String(description ?? '').trim(),
        updated_at:  new Date().toISOString(),
      })
      .eq('id', id);
    if (!isManager(req.auth)) updateQuery = updateQuery.eq('created_by', req.auth.username);
    const { data, error } = await updateQuery
      .select('id, title, created_by, created_at, updated_at')
      .maybeSingle();

    if (error) return serverError(res, error, 'ir-cases');
    if (!data)  return res.status(404).json({ error: 'Case not found.' });
    return res.status(200).json({ ok: true, case: data });
  }

  if (req.method === 'DELETE') {
    if (deployEnv === 'dev') return res.status(403).json({ error: 'Case deletion disabled while workspace history is retained.' });
    // Keep legacy production deletion; marker FK protects marked cases even if a scope check races.
    if (req.auth.role === 'l1') return res.status(403).json({ error: 'Forbidden: your role cannot delete cases.' });
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }
    const { id } = body ?? {};
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id)) return res.status(400).json({ error: 'Invalid id.' });
    const { data: scope, error: scopeError } = await supabase.from('ir_case_dev_scope').select('case_id').eq('case_id', id).maybeSingle();
    if (scopeError) return serverError(res, scopeError, 'ir-cases scope');
    if (scope) return res.status(404).json({ error: 'Case not found.' });
    let deleteQuery = supabase.from('ir_cases').delete().eq('id', id);
    if (!isManager(req.auth)) deleteQuery = deleteQuery.eq('created_by', req.auth.username);
    const { error } = await deleteQuery;
    if (error) return serverError(res, error, 'ir-cases');
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};

// Exposed for unit tests (the handler is the default export above).
module.exports.sanitizeSearchTerm = sanitizeSearchTerm;
