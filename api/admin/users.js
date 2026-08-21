const bcrypt = require('bcryptjs');
const { requireCurrentRole, readJsonBody } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const VALID_ROLES = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];

function mutationError(res, error, context) {
  if (error?.code === '23505') return res.status(409).json({ error: 'Username already exists.' });
  if (error?.code === 'P0002') return res.status(404).json({ error: 'User not found.' });
  if (error?.code === '22023') return res.status(400).json({ error: 'Invalid user mutation.' });
  if (error?.code === 'PGRST202') return res.status(503).json({ error: 'Run supabase/security_hardening.sql before managing users.' });
  return serverError(res, error, context);
}

async function mutateUser(supabase, req, operation, values) {
  return supabase.rpc('mutate_app_user', {
    p_actor_id: req.auth.userId,
    p_operation: operation,
    p_target_id: values.id || null,
    p_username: values.username || null,
    p_password_hash: values.passwordHash || null,
    p_role: values.role || null,
    p_detail: values.detail || null,
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured.' });
  if (!await requireCurrentRole(req, res, supabase, ['admin', 'l2'])) return;

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('app_users')
      .select('id, username, role, created_at, created_by')
      .order('created_at', { ascending: true });
    if (error) return serverError(res, error, 'admin/users GET');
    return res.status(200).json({ ok: true, users: data });
  }

  let body = {};
  try { body = await readJsonBody(req); }
  catch { return res.status(400).json({ error: 'Invalid JSON.' }); }

  if (req.method === 'POST') {
    const username = String(body?.username || '').trim();
    const password = String(body?.password || '');
    const role = body?.role;
    if (!username || !password || !role) return res.status(400).json({ error: 'Missing username, password, or role.' });
    if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await mutateUser(supabase, req, 'create', {
      username, passwordHash, role, detail: { role },
    });
    if (result.error) return mutationError(res, result.error, 'admin/users POST');
    return res.status(201).json({ ok: true, user: result.data });
  }

  if (req.method === 'PATCH') {
    const { id, role, password } = body || {};
    const username = body?.username == null ? null : String(body.username).trim();
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (!role && !password && username == null) return res.status(400).json({ error: 'Provide username, role, or password to update.' });
    if (username != null && !username) return res.status(400).json({ error: 'Username cannot be empty.' });
    if (role && !VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    const passwordHash = password ? await bcrypt.hash(password, 12) : null;
    const result = await mutateUser(supabase, req, 'update', {
      id, username, passwordHash, role,
      detail: { usernameChanged: username != null, roleChanged: !!role, passwordChanged: !!password, newRole: role || undefined },
    });
    if (result.error) return mutationError(res, result.error, 'admin/users PATCH');
    return res.status(200).json({ ok: true, user: result.data });
  }

  if (req.method === 'DELETE') {
    const { id } = body || {};
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (id === req.auth.userId) return res.status(400).json({ error: 'Cannot delete your own account.' });
    const result = await mutateUser(supabase, req, 'delete', { id });
    if (result.error) return mutationError(res, result.error, 'admin/users DELETE');
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};

module.exports.mutateUser = mutateUser;
