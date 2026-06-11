'use strict';

/** Round-robin cursor — persists for the lifetime of a warm serverless instance. */
let rrIndex = 0;

function normalizeKey(key) {
  return typeof key === 'string' ? key.trim() : '';
}

/**
 * Collects unique VirusTotal API keys from the environment.
 * VT_API_KEY plus optional VT_API_KEY_2 … VT_API_KEY_10 (trimmed, deduped).
 */
function getVtKeys() {
  const seen = new Set();
  const keys = [];
  const add = (raw) => {
    const k = normalizeKey(raw);
    if (k && !seen.has(k)) {
      seen.add(k);
      keys.push(k);
    }
  };
  add(process.env.VT_API_KEY);
  for (let i = 2; i <= 10; i++) add(process.env[`VT_API_KEY_${i}`]);
  return keys;
}

/**
 * Keys for one outbound VT request, rotated so concurrent scans spread load
 * across keys instead of always hammering VT_API_KEY first.
 */
function getVtKeysForRequest() {
  const keys = getVtKeys();
  if (keys.length <= 1) return keys;
  const start = rrIndex % keys.length;
  rrIndex = (rrIndex + 1) % keys.length;
  return keys.slice(start).concat(keys.slice(0, start));
}

function vtErrorCode(data) {
  return data?.error?.code || '';
}

/** Daily/minute/monthly quota or per-minute burst limit (VT error codes). */
function isVtRateLimited(status, data) {
  if (status === 429) return true;
  const code = vtErrorCode(data);
  return code === 'QuotaExceededError' || code === 'TooManyRequestsError';
}

/** Invalid/inactive key — try the next configured key. */
function isVtBadKey(status, data) {
  const code = vtErrorCode(data);
  return (
    status === 401 ||
    code === 'WrongCredentialsError' ||
    code === 'AuthenticationRequiredError' ||
    code === 'UserNotActiveError'
  );
}

function shouldTryNextVtKey(status, data) {
  return isVtRateLimited(status, data) || isVtBadKey(status, data);
}

module.exports = {
  getVtKeys,
  getVtKeysForRequest,
  isVtRateLimited,
  isVtBadKey,
  shouldTryNextVtKey,
};
