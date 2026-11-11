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

module.exports = {
  KEY_PREFIX, SCOPES, TYPES,
  hashApiKey, generateApiKey, readApiKey, normalizeScopes, normalizeTypes,
};
