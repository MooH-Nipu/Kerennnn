'use strict';

const { requireCurrentRole, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');
const { normalizeClientCode, isSchemaMissingError } = require('./team-filter');
const { getRoleContext } = require('./_tenancy');

const VALID_ROLES = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];

async function listClients(supabase) {
  const { data, error } = await supabase
    .from('charlie_filter_clients')
    .select('id,code,label,sort_order')
    .eq('active', true)
    .order('sort_order', { ascending: true })
    .order('label', { ascending: true });
  return { clients: data || [], error };
}

function mutationError(res, error) {
  const code = String(error?.code || '');
  if (isSchemaMissingError(error) || code === 'PGRST202') {
    return res.status(503).json({ error: 'Charlie client filters are not ready. Run required migration and reload schema.' });
  }
  if (code === '23505') return res.status(409).json({ error: 'Charlie client code already exists.' });
  if (code === 'P0002') return res.status(404).json({ error: 'Charlie client not found.' });
  if (code === '22023') return res.status(400).json({ error: error.message || 'Invalid Charlie client.' });
  if (code === '42501') return res.status(403).json({ error: 'Charlie client management denied.' });
  return serverError(res, error, 'charlie-clients mutation');
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET', 'POST', 'DELETE'].includes(req.method)) return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured.' });

  if (req.method === 'GET') {
    if (!await requireCurrentRole(req, res, supabase, VALID_ROLES)) return;
    const { allowedTeams } = getRoleContext(req.auth.role, req.auth.teamAccess);
    if (!allowedTeams.includes('CHARLIE')) return res.status(403).json({ error: 'Charlie client access denied.' });
    const { clients, error } = await listClients(supabase);
    if (error) {
      if (isSchemaMissingError(error)) return res.status(503).json({ error: 'Charlie client filters are not ready.' });
      return serverError(res, error, 'charlie-clients GET');
    }
    return res.status(200).json({ ok: true, clients });
  }

  if (!await requireCurrentRole(req, res, supabase, ['admin', 'soc_lead', 'l2'])) return;
  let body;
  try { body = await readJsonBody(req); }
  catch { return res.status(400).json({ error: 'Invalid JSON body.' }); }

  let code;
  try { code = normalizeClientCode(body?.code); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  if (code === 'GENERAL') return res.status(400).json({ error: 'GENERAL is reserved.' });

  if (req.method === 'DELETE') {
    const confirmation = typeof body?.confirmation === 'string' ? body.confirmation.trim() : '';
    if (confirmation !== code) return res.status(400).json({ error: `Type ${code} exactly to confirm deletion.` });
    const { data, error } = await supabase.rpc('delete_charlie_filter_client', {
      p_code: code,
      p_confirmation: confirmation,
      p_actor_id: req.auth.userId,
    });
    if (error) return mutationError(res, error);
    return res.status(200).json({ ok: true, deleted: data });
  }

  const label = typeof body?.label === 'string' ? body.label.trim() : '';
  if (!label || label.length > 64) return res.status(400).json({ error: 'Client label must be 1-64 characters.' });

  const { data, error } = await supabase.rpc('create_charlie_filter_client', {
    p_code: code,
    p_label: label,
    p_actor_id: req.auth.userId,
  });
  if (error) return mutationError(res, error);
  return res.status(201).json({ ok: true, client: data });
};

module.exports.listClients = listClients;
