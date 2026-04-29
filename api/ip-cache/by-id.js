const { createClient } = require('@supabase/supabase-js');
const { requireAuth } = require('../_auth');

function authEnabled() {
  return !!(process.env.APP_PASSWORD && process.env.APP_AUTH_SECRET);
}

function getSupabase() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key);
}

function isUuid(v) {
  const s = String(v || '').trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // Keep result access consistent with the app lock.
  if (authEnabled() && !requireAuth(req, res)) return;

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const id = req.query?.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'Missing/invalid ?id= (uuid).' });

  const { data, error } = await supabase
    .from('vt_ip_cache')
    .select(
      'id,ip,scan_count,first_scanned_at,last_scanned_at,vt_verdict,vt_stats,vt_payload,corr_confidence,corr_payload'
    )
    .eq('id', String(id))
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message || String(error) });
  if (!data) return res.status(404).json({ error: 'Not found' });

  return res.status(200).json({ ok: true, item: data });
};

