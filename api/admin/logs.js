'use strict';
const { requireRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const LIMIT = 100;

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  // Admin-tier only (admin, l2).
  if (!requireRole(req, res, ['admin', 'l2'])) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  try {
    const [auditRes, loginRes] = await Promise.all([
      supabase
        .from('audit_log')
        .select('id, actor_username, action, target, detail, created_at')
        .order('created_at', { ascending: false })
        .limit(LIMIT),
      supabase
        .from('login_attempts')
        .select('id, username, ip, success, attempted_at')
        .order('attempted_at', { ascending: false })
        .limit(LIMIT),
    ]);

    if (auditRes.error) return serverError(res, auditRes.error, 'admin/logs audit');
    if (loginRes.error) return serverError(res, loginRes.error, 'admin/logs login');

    return res.status(200).json({
      ok: true,
      audit: auditRes.data ?? [],
      logins: loginRes.data ?? [],
    });
  } catch (e) {
    return serverError(res, e, 'admin/logs');
  }
};
