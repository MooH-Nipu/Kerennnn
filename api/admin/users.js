const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const { requireRole, readJsonBody } = require('../_auth');

const VALID_ROLES = ['admin', 'pac', 'charlie', 'l1', 'l2'];

function getSupabase() {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!requireRole(req, res, ['admin'])) return;

  const supabase = getSupabase();

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('app_users')
      .select('id, username, role, created_at, created_by')
      .order('created_at', { ascending: true });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true, users: data });
  }

  if (req.method === 'POST') {
    let body = {};
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON.' });
    }

    const { username, password, role } = body || {};
    if (!username || !password || !role) {
      return res.status(400).json({ error: 'Missing username, password, or role.' });
    }
    if (!VALID_ROLES.includes(role)) {
      return res.status(400).json({ error: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}.` });
    }

    const hash = await bcrypt.hash(password, 12);
    const { data, error } = await supabase
      .from('app_users')
      .insert({ username: String(username).trim(), password_hash: hash, role, created_by: req.auth.userId })
      .select('id, username, role, created_at')
      .single();

    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Username already exists.' });
      return res.status(500).json({ error: error.message });
    }
    return res.status(201).json({ ok: true, user: data });
  }

  if (req.method === 'PATCH') {
    let body = {};
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON.' });
    }

    const { id, role, password } = body || {};
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (!role && !password) return res.status(400).json({ error: 'Provide role or password to update.' });

    const updates = {};
    if (role) {
      if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role.' });
      updates.role = role;
    }
    if (password) {
      updates.password_hash = await bcrypt.hash(password, 12);
    }

    const { data, error } = await supabase
      .from('app_users')
      .update(updates)
      .eq('id', id)
      .select('id, username, role')
      .single();

    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: 'User not found.' });
    return res.status(200).json({ ok: true, user: data });
  }

  if (req.method === 'DELETE') {
    let body = {};
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON.' });
    }

    const { id } = body || {};
    if (!id) return res.status(400).json({ error: 'Missing id.' });
    if (id === req.auth.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account.' });
    }

    const { error } = await supabase.from('app_users').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
