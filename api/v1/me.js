'use strict';
const { getSupabase } = require('../_supabase');
const { requireApiKey } = require('../_apikeys');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Use GET.' } });
  }
  const supabase = getSupabase();
  if (!await requireApiKey(req, res, supabase, null)) return;
  return res.status(200).json({
    ok: true,
    user: { username: req.apiKey.username, role: req.auth.role, teams: req.auth.teamAccess },
    key: { prefix: req.apiKey.prefix, scopes: req.apiKey.scopes, allowedTypes: req.apiKey.allowedTypes },
    endpoints: {
      scan: 'POST /api/v1/scan { "iocs": ["8.8.8.8"] }',
      verdict: 'GET /api/v1/verdict?ioc=8.8.8.8',
      me: 'GET /api/v1/me',
    },
  });
};
