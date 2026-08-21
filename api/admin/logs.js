'use strict';
const { requireCurrentRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

const LIMIT = 100;

function canReadSystemLogs(role) {
  return role === 'admin' || role === 'l2';
}

function mapTeamAudit(row) {
  return {
    id: `team-filter-${row.id}`,
    actor_username: row.actor_username,
    action: `team_filter.${row.operation}`,
    target: row.team,
    detail: {
      status: row.status,
      item_count: row.item_count,
      execution_time_ms: row.execution_time_ms,
      ...(row.detail || {}),
    },
    created_at: row.created_at,
  };
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }
  if (!await requireCurrentRole(req, res, supabase, ['admin', 'soc_lead', 'l2'])) return;

  try {
    const makeTeamQuery = () => supabase
      .from('team_filter_audit')
      .select('id, actor_username, team, operation, item_count, execution_time_ms, status, detail, created_at')
      .order('created_at', { ascending: false })
      .limit(LIMIT);

    if (!canReadSystemLogs(req.auth.role)) {
      const teamRes = await makeTeamQuery();
      if (teamRes.error) {
        if (['42P01', 'PGRST204', 'PGRST205'].includes(String(teamRes.error.code || ''))) {
          return res.status(200).json({ ok: true, audit: [], logins: [], schemaReady: false });
        }
        return serverError(res, teamRes.error, 'admin/logs team audit');
      }
      return res.status(200).json({ ok: true, audit: (teamRes.data ?? []).map(mapTeamAudit), logins: [], schemaReady: true });
    }

    const [auditRes, loginRes, teamRes] = await Promise.all([
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
      makeTeamQuery(),
    ]);

    if (auditRes.error) return serverError(res, auditRes.error, 'admin/logs audit');
    if (loginRes.error) return serverError(res, loginRes.error, 'admin/logs login');
    const teamMissing = teamRes.error && ['42P01', 'PGRST204', 'PGRST205'].includes(String(teamRes.error.code || ''));
    if (teamRes.error && !teamMissing) return serverError(res, teamRes.error, 'admin/logs team audit');

    return res.status(200).json({
      ok: true,
      audit: [...(auditRes.data ?? []), ...((teamRes.data ?? []).map(mapTeamAudit))]
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
        .slice(0, LIMIT),
      logins: loginRes.data ?? [],
      schemaReady: !teamMissing,
    });
  } catch (e) {
    return serverError(res, e, 'admin/logs');
  }
};

module.exports.mapTeamAudit = mapTeamAudit;
module.exports.canReadSystemLogs = canReadSystemLogs;
