const bcrypt = require('bcryptjs');
const { requireCurrentRole, readJsonBody } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const ASSIGNABLE_ROLES = ['admin', 'soc_lead', 'l1', 'l2'];
const VALID_TEAMS = ['PAC', 'CHARLIE'];

// The L2 tier manages analysts, not the admin tier. Without this an L2 account
// could mint an admin, reset an admin password, or delete an admin.
function canAssignRole(actorRole, role) {
  return actorRole === 'admin' || role !== 'admin';
}

function canManageTarget(actorRole, targetRole) {
  return actorRole === 'admin' || targetRole !== 'admin';
}

async function loadTargetRole(supabase, id) {
  const { data, error } = await supabase.from('app_users').select('role').eq('id', id).maybeSingle();
  return { role: data?.role ?? null, error };
}

function sanitizeTeamAccess(value, optional = false) {
  if (value === undefined && optional) return null;
  if (!Array.isArray(value)) throw new Error('Team access must be an array.');
  const normalized = value.map(team => String(team).trim().toUpperCase());
  if (normalized.some(team => !VALID_TEAMS.includes(team))) throw new Error('Team access values must be PAC or CHARLIE.');
  return VALID_TEAMS.filter(team => normalized.includes(team));
}

function mutationError(res, error, context) {
  if (error?.code === '23505') return res.status(409).json({ error: 'Username already exists.' });
  if (error?.code === 'P0002') return res.status(404).json({ error: 'User not found.' });
  if (error?.code === '22023') return res.status(400).json({ error: 'Invalid user mutation.' });
  if (error?.code === 'PGRST202') return res.status(503).json({ error: 'Run supabase/security_hardening.sql before managing users.' });
  return serverError(res, error, context);
}

async function mutateUser(supabase, req, operation, values) {
  return supabase.rpc('mutate_app_user_v2', {
    p_actor_id: req.auth.userId,
    p_operation: operation,
    p_target_id: values.id || null,
    p_username: values.username || null,
    p_password_hash: values.passwordHash || null,
    p_role: values.role || null,
    p_detail: values.detail || null,
    p_team_access: values.teamAccess ?? null,
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
      .select('id, username, role, team_access, created_at, created_by')
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
    let teamAccess;
    try { teamAccess = sanitizeTeamAccess(body?.teamAccess, true); }
    catch (error) { return res.status(400).json({ error: error.message }); }
    if (!username || !password || !role) return res.status(400).json({ error: 'Missing username, password, or role.' });
    if (!ASSIGNABLE_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    if (!canAssignRole(req.auth.role, role)) return res.status(403).json({ error: 'Only admins can assign the admin role.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await mutateUser(supabase, req, 'create', {
      username, passwordHash, role, teamAccess, detail: { role, teamAccess },
    });
    if (result.error) return mutationError(res, result.error, 'admin/users POST');
    return res.status(201).json({ ok: true, user: result.data });
  }

  if (req.method === 'PATCH') {
    const { id, role, password } = body || {};
    const hasTeamAccess = Object.prototype.hasOwnProperty.call(body || {}, 'teamAccess');
    let teamAccess = null;
    if (hasTeamAccess) {
      try { teamAccess = sanitizeTeamAccess(body.teamAccess); }
      catch (error) { return res.status(400).json({ error: error.message }); }
    }
    const username = body?.username == null ? null : String(body.username).trim();
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (!role && !password && username == null && !hasTeamAccess) return res.status(400).json({ error: 'Provide username, role, team access, or password to update.' });
    if (username != null && !username) return res.status(400).json({ error: 'Username cannot be empty.' });
    if (role && !ASSIGNABLE_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
    if (role && !canAssignRole(req.auth.role, role)) return res.status(403).json({ error: 'Only admins can assign the admin role.' });
    if (id === req.auth.userId && role && role !== req.auth.role) return res.status(400).json({ error: 'Cannot change your own role.' });
    if (req.auth.role !== 'admin') {
      const target = await loadTargetRole(supabase, id);
      if (target.error) return serverError(res, target.error, 'admin/users target');
      if (!target.role) return res.status(404).json({ error: 'User not found.' });
      if (!canManageTarget(req.auth.role, target.role)) return res.status(403).json({ error: 'Only admins can modify an admin account.' });
    }
    const passwordHash = password ? await bcrypt.hash(password, 12) : null;
    const result = await mutateUser(supabase, req, 'update', {
      id, username, passwordHash, role, teamAccess,
      detail: { usernameChanged: username != null, roleChanged: !!role, teamAccessChanged: hasTeamAccess, passwordChanged: !!password, newRole: role || undefined, teamAccess: teamAccess ?? undefined },
    });
    if (result.error) return mutationError(res, result.error, 'admin/users PATCH');
    return res.status(200).json({ ok: true, user: result.data });
  }

  if (req.method === 'DELETE') {
    const { id } = body || {};
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (id === req.auth.userId) return res.status(400).json({ error: 'Cannot delete your own account.' });
    if (req.auth.role !== 'admin') {
      const target = await loadTargetRole(supabase, id);
      if (target.error) return serverError(res, target.error, 'admin/users target');
      if (!target.role) return res.status(404).json({ error: 'User not found.' });
      if (!canManageTarget(req.auth.role, target.role)) return res.status(403).json({ error: 'Only admins can delete an admin account.' });
    }
    const result = await mutateUser(supabase, req, 'delete', { id });
    if (result.error) return mutationError(res, result.error, 'admin/users DELETE');
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};

module.exports.mutateUser = mutateUser;
module.exports.sanitizeTeamAccess = sanitizeTeamAccess;
module.exports.canAssignRole = canAssignRole;
module.exports.canManageTarget = canManageTarget;
