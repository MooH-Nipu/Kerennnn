'use strict';

const { revalidateRequestIdentity } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { getApiRoute } = require('./_routes');

const PUBLIC_ROUTES = new Set(['/api/health', '/api/auth/login', '/api/auth/logout']);
const TEAM_METHODS = new Set(['GET', 'POST', 'DELETE', 'OPTIONS']);

module.exports = async function handler(req, res) {
  const rawPath = Array.isArray(req.query?.path) ? req.query.path.join('/') : String(req.query?.path || '');
  const pathname = `/api/${rawPath.replace(/^\/+/, '')}`;
  const route = getApiRoute(pathname);
  if (!route) return res.status(404).json({ error_code: 'ERR_ROUTE_NOT_FOUND', message: 'API route not found.' });

  const unsupportedTeamFilterMethod = pathname === '/api/v1/team-filter' && !TEAM_METHODS.has(req.method);
  const needsIdentity = req.method !== 'OPTIONS' && !unsupportedTeamFilterMethod && !PUBLIC_ROUTES.has(pathname);
  if (needsIdentity) {
    const supabase = getSupabase();
    if (!supabase) return res.status(503).json({ error: 'Unable to validate current account.' });
    req.path = pathname;
    if (!await revalidateRequestIdentity(req, res, supabase)) return;
  }
  return route.handler(req, res);
};
