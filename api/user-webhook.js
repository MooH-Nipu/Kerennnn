'use strict';
const { requireAuth, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

function isValidWebhookUrl(u) {
  try {
    return new URL(u).protocol === 'https:';
  } catch {
    return false;
  }
}

// Per-user MALICIOUS alert webhook config. Strictly scoped to req.auth.userId.
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  const userId = req.auth.userId;

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('user_webhooks')
      .select('webhook_url, enabled, min_confidence')
      .eq('user_id', userId)
      .maybeSingle();
    if (error) return serverError(res, error, 'user-webhook GET');
    return res.status(200).json({
      ok: true,
      webhook_url: data?.webhook_url ?? '',
      enabled: data?.enabled ?? true,
      min_confidence: data?.min_confidence ?? 70,
    });
  }

  if (req.method === 'PUT') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON.' });
    }

    const webhook_url = String(body?.webhook_url ?? '').trim();
    const enabled = body?.enabled !== false;
    let min_confidence = Number(body?.min_confidence);
    if (!Number.isFinite(min_confidence)) min_confidence = 70;
    min_confidence = Math.min(100, Math.max(0, Math.round(min_confidence)));

    if (webhook_url && !isValidWebhookUrl(webhook_url))
      return res.status(400).json({ error: 'Webhook URL must be a valid https:// URL.' });

    const { error } = await supabase.from('user_webhooks').upsert(
      {
        user_id: userId,
        username: req.auth.username ?? null,
        webhook_url,
        enabled,
        min_confidence,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'user_id' }
    );
    if (error) return serverError(res, error, 'user-webhook PUT');
    return res.status(200).json({ ok: true, webhook_url, enabled, min_confidence });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};
