'use strict';
const { requireAuth } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const id = String(req.query?.id ?? '').trim();
  if (!id) return res.status(400).json({ error: 'Missing id.' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }
  const { data, error } = await supabase
    .from('ir_cases')
    .select('id, title, description, created_by, created_at, updated_at')
    .eq('id', id)
    .single();

  if (error) return serverError(res, error, 'ir-cases detail');
  if (!data)  return res.status(404).json({ error: 'Case not found.' });
  return res.status(200).json({ ok: true, case: data });
};
