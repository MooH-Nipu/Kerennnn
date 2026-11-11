'use strict';
const { requireCurrentRole, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');
const { writeAudit } = require('./_audit');
const { generateApiKey, normalizeScopes, normalizeTypes } = require('./_apikeys');

const ROLES = ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2'];
const COLS = 'id,label,key_prefix,scopes,allowed_types,enabled,last_used_at,created_at';
// A user may hold several keys (one per integration). The cap only stops runaway
// scripts from creating hundreds of rows; raise API_MAX_KEYS_PER_USER if needed.
const MAX_KEYS = Math.min(Number.parseInt(process.env.API_MAX_KEYS_PER_USER, 10) || 10, 25);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function toMetadata(row) {
  return {
    id: row.id,
    label: row.label || null,
    prefix: row.key_prefix,
    scopes: row.scopes || [],
    allowedTypes: row.allowed_types || [],
    enabled: row.enabled !== false,
    lastUsedAt: row.last_used_at || null,
    createdAt: row.created_at,
  };
}

function badRequest(res, code, message) {
  return res.status(400).json({ ok: false, error: { code, message } });
}

async function listLiveKeys(supabase, userId) {
  return supabase
    .from('api_keys')
    .select(COLS)
    .eq('user_id', userId)
    .is('revoked_at', null)
    .order('created_at', { ascending: false });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ ok: false, error: 'Supabase is not configured.' });
  if (!await requireCurrentRole(req, res, supabase, ROLES)) return;

  const userId = req.auth.userId;

  if (req.method === 'GET') {
    const { data, error } = await listLiveKeys(supabase, userId);
    if (error) return serverError(res, error, 'api-keys list');
    return res.status(200).json({ ok: true, keys: (data || []).map(toMetadata) });
  }

  if (req.method === 'POST') {
    const body = (await readJsonBody(req).catch(() => ({}))) || {};
    const existing = await listLiveKeys(supabase, userId);
    if (existing.error) return serverError(res, existing.error, 'api-keys count');
    if ((existing.data || []).length >= MAX_KEYS) {
      return res.status(409).json({
        ok: false,
        error: { code: 'KEY_LIMIT_REACHED', message: `Limit is ${MAX_KEYS} live keys. Revoke one first.` },
      });
    }

    const label = typeof body.label === 'string' ? body.label.trim().slice(0, 60) : '';
    const { key, prefix, hash } = generateApiKey();
    const row = {
      user_id: userId,
      username: req.auth.username || null,
      label: label || null,
      key_prefix: prefix,
      key_hash: hash,
      scopes: normalizeScopes(body.scopes),
      allowed_types: normalizeTypes(body.allowedTypes),
    };
    const { data, error } = await supabase.from('api_keys').insert(row).select(COLS).maybeSingle();
    if (error) return serverError(res, error, 'api-keys insert');

    writeAudit(supabase, {
      actorId: userId, actorUsername: req.auth.username,
      action: 'api_key.create', target: prefix,
      detail: `label=${row.label || '-'} scopes=${row.scopes.join(',')} types=${row.allowed_types.join(',')}`,
    }).catch(() => {});

    // `secret` is returned exactly once and never stored.
    return res.status(201).json({ ok: true, key: toMetadata(data), secret: key });
  }

  if (req.method === 'PATCH') {
    const body = (await readJsonBody(req).catch(() => ({}))) || {};
    const id = String(body.id || '');
    if (!UUID_RE.test(id)) return badRequest(res, 'MISSING_KEY_ID', 'Send the key id to update.');

    const patch = {};
    if (typeof body.label === 'string') patch.label = body.label.trim().slice(0, 60) || null;
    if (Array.isArray(body.scopes)) patch.scopes = normalizeScopes(body.scopes);
    if (Array.isArray(body.allowedTypes)) patch.allowed_types = normalizeTypes(body.allowedTypes);
    if (typeof body.enabled === 'boolean') patch.enabled = body.enabled;
    if (!Object.keys(patch).length) {
      return badRequest(res, 'NOTHING_TO_UPDATE', 'Send label, scopes, allowedTypes or enabled.');
    }

    // Ownership is part of the WHERE clause: a foreign id updates zero rows.
    const { data, error } = await supabase
      .from('api_keys')
      .update(patch)
      .eq('id', id)
      .eq('user_id', userId)
      .is('revoked_at', null)
      .select(COLS)
      .maybeSingle();
    if (error) return serverError(res, error, 'api-keys patch');
    if (!data) return res.status(404).json({ ok: false, error: { code: 'KEY_NOT_FOUND', message: 'No such key.' } });

    writeAudit(supabase, {
      actorId: userId, actorUsername: req.auth.username,
      action: 'api_key.update', target: data.key_prefix, detail: JSON.stringify(patch),
    }).catch(() => {});

    return res.status(200).json({ ok: true, key: toMetadata(data) });
  }

  if (req.method === 'DELETE') {
    // Revoke is addressed by query string only (?id=…): no body means the shared
    // JSON reader never has to touch the request stream.
    const id = String(req.query?.id || '');
    if (!UUID_RE.test(id)) return badRequest(res, 'MISSING_KEY_ID', 'Send ?id=<key uuid>.');

    const { data, error } = await supabase
      .from('api_keys')
      .update({ revoked_at: new Date().toISOString(), enabled: false })
      .eq('id', id)
      .eq('user_id', userId)
      .is('revoked_at', null)
      .select(COLS)
      .maybeSingle();
    if (error) return serverError(res, error, 'api-keys revoke');
    if (!data) return res.status(404).json({ ok: false, error: { code: 'KEY_NOT_FOUND', message: 'No such key.' } });

    writeAudit(supabase, {
      actorId: userId, actorUsername: req.auth.username,
      action: 'api_key.revoke', target: data.key_prefix, detail: null,
    }).catch(() => {});

    return res.status(200).json({ ok: true, key: null });
  }

  return res.status(405).json({ ok: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'GET/POST/PATCH/DELETE only.' } });
};
