const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

function isUuid(v) {
  const s = String(v || '').trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
}

// Shared (non-key) columns selected from either cache table.
const COLS =
  'id,scan_count,first_scanned_at,last_scanned_at,vt_verdict,vt_stats,vt_payload,corr_confidence,corr_payload';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const id = req.query?.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'Missing/invalid ?id= (uuid).' });

  // 1) IP cache (keyed by ip). Normalize to the generic { ioc, ioc_type } shape.
  {
    const { data, error } = await supabase
      .from('vt_ip_cache')
      .select(`ip,${COLS}`)
      .eq('id', String(id))
      .maybeSingle();
    if (error) return serverError(res, error, 'ip-cache by-id');
    if (data) {
      return res.status(200).json({ ok: true, item: { ...data, ioc: data.ip, ioc_type: 'ip' } });
    }
  }

  // 2) Generic IOC cache (domain/hash, keyed by ioc+ioc_type). Degrades gracefully
  //    to 404 if the table is not migrated yet (no non-IP links would exist then).
  {
    const { data, error } = await supabase
      .from('vt_ioc_cache')
      .select(`ioc,ioc_type,${COLS}`)
      .eq('id', String(id))
      .maybeSingle();
    if (!error && data) {
      return res.status(200).json({ ok: true, item: { ...data, ip: data.ioc } });
    }
  }

  return res.status(404).json({ error: 'Not found' });
};
