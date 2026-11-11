'use strict';
const crypto = require('node:crypto');

const KEY_PREFIX = 'krn';
const SCOPES = ['ioc:scan', 'ioc:read'];
const TYPES = ['ip', 'domain', 'hash'];

/** sha256 hex of the full key. The DB stores only this. */
function hashApiKey(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex');
}

/**
 * key    = krn_<8 hex>_<32 url-safe chars>
 * prefix = krn_<8 hex>  (shown in the UI, safe to log)
 */
function generateApiKey() {
  const id = crypto.randomBytes(4).toString('hex');
  const secret = crypto.randomBytes(24).toString('base64url');
  const key = `${KEY_PREFIX}_${id}_${secret}`;
  return { key, prefix: `${KEY_PREFIX}_${id}`, hash: hashApiKey(key) };
}

/** Reads the key from Authorization: Bearer … or X-API-Key. */
function readApiKey(req) {
  const header = String(req?.headers?.authorization || '');
  const bearer = header.match(/^Bearer\s+(.+)$/i);
  if (bearer) return bearer[1].trim();
  const alt = req?.headers?.['x-api-key'];
  return typeof alt === 'string' ? alt.trim() : '';
}

/** Keeps only known scopes, de-duplicated, in canonical order. Empty → default. */
function normalizeScopes(input) {
  const wanted = Array.isArray(input) ? input.map(String) : [];
  const kept = SCOPES.filter(scope => wanted.includes(scope));
  return kept.length ? kept : ['ioc:scan'];
}

/** Keeps only known IOC types. Empty → all types. */
function normalizeTypes(input) {
  const wanted = Array.isArray(input) ? input.map(String) : [];
  const kept = TYPES.filter(type => wanted.includes(type));
  return kept.length ? kept : [...TYPES];
}

function deny(res, status, code, message) {
  res.status(status).json({ error: { code, message } });
  return false;
}

/**
 * Authenticates an API-key request and injects the same req.auth shape the
 * session wrapper produces, so existing handlers need no changes.
 * `scope` is enforced when provided.
 */
async function requireApiKey(req, res, supabase, scope) {
  if (!supabase) return deny(res, 503, 'SERVICE_UNAVAILABLE', 'Supabase is not configured.');
  const raw = readApiKey(req);
  if (!raw) return deny(res, 401, 'MISSING_API_KEY', 'Send Authorization: Bearer <key>.');

  const { data: key, error } = await supabase
    .from('api_keys')
    .select('id,user_id,username,key_prefix,scopes,allowed_types,enabled,revoked_at')
    .eq('key_hash', hashApiKey(raw))
    .is('revoked_at', null)
    .maybeSingle();
  if (error) return deny(res, 503, 'KEY_LOOKUP_FAILED', 'Unable to verify the API key.');
  if (!key || key.enabled !== true) return deny(res, 401, 'INVALID_API_KEY', 'API key is not valid.');

  const scopes = Array.isArray(key.scopes) ? key.scopes : [];
  if (scope && !scopes.includes(scope)) {
    return deny(res, 403, 'SCOPE_NOT_ALLOWED', `This key lacks the "${scope}" scope.`);
  }

  const { data: user, error: userError } = await supabase
    .from('app_users')
    .select('id,username,role,team_access')
    .eq('id', key.user_id)
    .maybeSingle();
  if (userError) return deny(res, 503, 'USER_LOOKUP_FAILED', 'Unable to resolve the key owner.');
  if (!user) return deny(res, 401, 'KEY_OWNER_MISSING', 'The key owner no longer exists.');

  req.apiKey = {
    id: key.id,
    prefix: key.key_prefix,
    scopes,
    allowedTypes: Array.isArray(key.allowed_types) ? key.allowed_types : TYPES,
    userId: user.id,
    username: user.username,
  };
  req.auth = {
    userId: user.id,
    username: user.username,
    role: user.role,
    teamAccess: Array.isArray(user.team_access) ? user.team_access : [],
  };
  req.authCurrent = true;
  res.setHeader('X-API-Key-Prefix', key.key_prefix);

  // Touch last_used_at without blocking the scan.
  Promise.resolve(
    supabase.from('api_keys').update({ last_used_at: new Date().toISOString() }).eq('id', key.id)
  ).catch(() => {});

  return true;
}

module.exports = {
  KEY_PREFIX, SCOPES, TYPES,
  hashApiKey, generateApiKey, readApiKey, normalizeScopes, normalizeTypes,
  requireApiKey,
};
