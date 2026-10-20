'use strict';
const net = require('node:net');
const { requireCurrentRole, readJsonBody } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const roles = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];
const statuses = ['open', 'investigating', 'contained', 'closed'];
function canAccess(auth, row) {
  // ponytail: legacy cases have creator username, no team column; add explicit case membership before team sharing.
  return ['admin', 'soc_lead'].includes(auth.role) || row.created_by === auth.username;
}
function normalizeIoc(type, raw) {
  if (typeof raw !== 'string') return null;
  const value = raw.trim();
  if (!value || value.length > 2048 || [...value].some(ch => ch.charCodeAt(0) < 32 || ch.charCodeAt(0) === 127)) return null;
  if (type === 'ip') return net.isIP(value) ? value.toLowerCase() : null;
  if (type === 'domain') return value.length <= 253 && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value) ? value.toLowerCase() : null;
  if (type === 'hash') return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value) ? value.toLowerCase() : null;
  if (type === 'url') {
    try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && url.hostname && !url.username && !url.password && url.href.length <= 2041 ? url.href : null; } catch { return null; }
  }
  return null;
}
function plainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function allowedKeys(v, keys) { return plainObject(v) && Object.keys(v).every(key => keys.includes(key)); }
function pagination(query) {
  const parse = (v, fallback, max) => v === undefined ? fallback : typeof v === 'string' && /^\d+$/.test(v) && Number(v) <= max ? Number(v) : null;
  const limit = parse(query?.limit, 25, 50);
  const offset = parse(query?.offset, 0, 10000);
  return limit && offset !== null ? { limit, offset } : null;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET', 'POST', 'PATCH'].includes(req.method)) return res.status(405).json({ error: 'Method not allowed.' });
  if (process.env.KERENNNN_DEPLOY_ENV !== 'dev') return res.status(404).json({ error: 'Not found.' });
  const db = getSupabase();
  if (!db) return res.status(503).json({ error: 'Supabase unavailable.' });
  if (!await requireCurrentRole(req, res, db, roles)) return;
  const id = req.method === 'GET' ? req.query?.id : req.body?.id;
  let body = {};
  if (req.method !== 'GET') {
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }
  }
  const caseId = req.method === 'GET' ? id : body?.id;
  if (typeof caseId !== 'string' || !UUID.test(caseId)) return res.status(400).json({ error: 'Invalid case id.' });
  const { data: scope, error: scopeError } = await db.from('ir_case_dev_scope').select('case_id').eq('case_id', caseId).maybeSingle();
  if (scopeError) return serverError(res, scopeError, 'workspace scope');
  if (!scope) return res.status(404).json({ error: 'Case not found.' });
  const { data: caseRow, error: caseError } = await db.from('ir_cases').select('id,title,description,created_by,created_at,updated_at,status').eq('id', caseId).maybeSingle();
  if (caseError) return serverError(res, caseError, 'workspace case');
  if (!caseRow || !canAccess(req.auth, caseRow)) return res.status(404).json({ error: 'Case not found.' });
  if (req.method === 'GET') {
    const page = pagination(req.query);
    if (!page) return res.status(400).json({ error: 'Invalid pagination.' });
    const results = await Promise.all([
      db.from('ir_case_notes').select('id,body,author_id,created_at').eq('case_id', caseId).order('created_at', { ascending: false }).order('id', { ascending: false }).range(page.offset, page.offset + page.limit - 1),
      db.from('ir_case_iocs').select('id,ioc_type,value,linked_by,created_at').eq('case_id', caseId).order('created_at', { ascending: false }).order('id', { ascending: false }).range(page.offset, page.offset + page.limit - 1),
      db.from('ir_case_events').select('id,event_type,actor_id,detail,created_at').eq('case_id', caseId).order('id', { ascending: false }).range(page.offset, page.offset + page.limit - 1),
    ]);
    const failed = results.find(r => r.error);
    if (failed) return serverError(res, failed.error, 'workspace list');
    return res.status(200).json({ ok: true, case: caseRow, notes: results[0].data ?? [], iocs: results[1].data ?? [], events: results[2].data ?? [], offset: page.offset, limit: page.limit, hasMore: results.map(r => (r.data ?? []).length === page.limit) });
  }
  if (req.method === 'POST') {
    if (!allowedKeys(body, ['id', 'kind', 'body', 'ioc_type', 'value'])) return res.status(400).json({ error: 'Invalid payload.' });
    if (body.kind === 'note' && Object.keys(body).every(k => ['id','kind','body'].includes(k))) {
      if (typeof body.body !== 'string' || !body.body.trim() || body.body.trim().length > 4000) return res.status(400).json({ error: 'Invalid note.' });
      const result = await db.from('ir_case_notes').insert({ case_id: caseId, body: body.body.trim(), author_id: req.auth.userId }).select('id,body,author_id,created_at').single();
      if (result.error) return serverError(res, result.error, 'workspace note');
      return res.status(201).json({ ok: true, note: result.data });
    }
    if (body.kind === 'ioc' && Object.keys(body).every(k => ['id','kind','ioc_type','value'].includes(k))) {
      const value = normalizeIoc(body.ioc_type, body.value);
      if (!value) return res.status(400).json({ error: 'Invalid IOC.' });
      const result = await db.from('ir_case_iocs').insert({ case_id: caseId, ioc_type: body.ioc_type, value, linked_by: req.auth.userId }).select('id,ioc_type,value,linked_by,created_at').single();
      if (result.error?.code === '23505') return res.status(409).json({ error: 'IOC already linked.' });
      if (result.error) return serverError(res, result.error, 'workspace IOC');
      return res.status(201).json({ ok: true, ioc: result.data });
    }
    return res.status(400).json({ error: 'Invalid payload.' });
  }
  if (!allowedKeys(body, ['id','status']) || !statuses.includes(body.status)) return res.status(400).json({ error: 'Invalid status.' });
  const { error } = await db.rpc('ir_workspace_set_dev_status', { p_case_id: caseId, p_status: body.status, p_actor_id: req.auth.userId, p_creator_id: canAccess(req.auth, { created_by: '' }) ? null : req.auth.userId });
  if (error) return serverError(res, error, 'workspace status');
  return res.status(200).json({ ok: true, status: body.status });
};
module.exports.normalizeIoc = normalizeIoc;
module.exports.canAccess = canAccess;
module.exports.pagination = pagination;
