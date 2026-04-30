const { createClient } = require('@supabase/supabase-js');
const { normalizeIpLine } = require('../_ioc');
const { readJsonBody } = require('../_auth');

function getSupabase() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  let body = {};
  try {
    body = await readJsonBody(req);
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body.' });
  }

  const iocRaw = body && (body.ioc || body.ip);
  const ip = normalizeIpLine(iocRaw);
  if (!ip) return res.status(400).json({ error: 'Invalid or missing ip/ioc (must be an IP).' });

  const corr = body && body.correlation;
  if (!corr || typeof corr !== 'object') return res.status(400).json({ error: 'Missing correlation object.' });

  const confidence =
    corr && corr.confidence !== undefined && corr.confidence !== null ? Number(corr.confidence) : null;
  const corrPayload = corr;

  // Merge corr_* only; does not bump last_scanned_at (TTL is keyed off first_scanned_at).
  const { error } = await supabase.from('vt_ip_cache').upsert(
    {
      ip,
      corr_confidence: Number.isFinite(confidence) ? Math.round(confidence) : null,
      corr_payload: corrPayload,
    },
    { onConflict: 'ip' }
  );

  if (error) return res.status(500).json({ error: error.message || String(error) });
  return res.status(200).json({ ok: true });
};

