'use strict';
const { requireCurrentRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const id = String(req.query?.id ?? '').trim();
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id)) return res.status(400).json({ error: 'Invalid id.' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }
  if (!await requireCurrentRole(req, res, supabase, ['admin','soc_lead','pac','charlie','l1','l2'])) return;
  const deployEnv = process.env.KERENNNN_DEPLOY_ENV;
  if (deployEnv !== 'prod' && deployEnv !== 'dev') return res.status(503).json({ error: 'Deployment environment is not configured.' });
  let query = supabase
    .from('ir_cases')
    .select('id, title, description, created_by, created_at, updated_at')
    .eq('id', id);
  query = query.select(`id, title, description, created_by, created_at, updated_at, ir_case_dev_scope!${deployEnv === 'dev' ? 'inner' : 'left'}(case_id)`);
  if (deployEnv === 'prod') query = query.is('ir_case_dev_scope', null);
  if (!['admin', 'soc_lead'].includes(req.auth.role)) query = query.eq('created_by', req.auth.username);
  const { data, error } = await query.maybeSingle();

  if (error) return serverError(res, error, 'ir-cases detail');
  if (!data)  return res.status(404).json({ error: 'Case not found.' });
  return res.status(200).json({ ok: true, case: { id: data.id, title: data.title, description: data.description, created_by: data.created_by, created_at: data.created_at, updated_at: data.updated_at } });
};
