'use strict';

/** Round-robin cursor — persists for the lifetime of a warm server instance. */
let rrIndex = 0;

/**
 * Per-key cooldown: maps key → Unix timestamp (ms) after which it is usable again.
 * Set by markVtKeyRateLimited() when a key returns 429. Checked by getVtKeysForRequest()
 * so the next request skips cooling-down keys instead of burning an attempt on them.
 */
const keyCooldownUntil = new Map();

const VT_RATE_LIMIT_COOLDOWN_MS = 61_000; // 1s buffer over VT's 60s window

function normalizeKey(key) {
  return typeof key === 'string' ? key.trim() : '';
}

/**
 * Collects unique VirusTotal API keys from the environment.
 * VT_API_KEY plus any numbered VT_API_KEY_N entries (trimmed, deduped).
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
  Object.keys(process.env)
    .map((name) => ({ name, match: /^VT_API_KEY_(\d+)$/.exec(name) }))
    .filter(({ match }) => match && Number(match[1]) >= 2)
    .sort((a, b) => Number(a.match[1]) - Number(b.match[1]))
    .forEach(({ name }) => add(process.env[name]));
  return keys;
}

/** Mark a key as rate-limited; it will be skipped for cooldownMs (default 61s). */
function markVtKeyRateLimited(key, cooldownMs = VT_RATE_LIMIT_COOLDOWN_MS) {
  if (key) keyCooldownUntil.set(key, Date.now() + cooldownMs);
}

/** True if this key is still in its rate-limit cooldown window. */
function isVtKeyCoolingDown(key) {
  const until = keyCooldownUntil.get(key);
  if (!until) return false;
  if (Date.now() >= until) {
    keyCooldownUntil.delete(key); // expired — clean up
    return false;
  }
  return true;
}

/**
 * Keys for one outbound VT request, rotated so concurrent scans spread load.
 * Keys currently in cooldown (recently 429'd) are moved to the END so the loop
 * reaches healthy keys first without wasting a round-trip on a known-hot key.
 */
function getVtKeysForRequest() {
  const keys = getVtKeys();
  if (keys.length <= 1) return keys;

  // Rotate starting position for even load distribution across requests.
  const start = rrIndex % keys.length;
  rrIndex = (rrIndex + 1) % keys.length;
  const rotated = keys.slice(start).concat(keys.slice(0, start));

  // Partition: available keys first, cooling-down keys last.
  const available = rotated.filter(k => !isVtKeyCoolingDown(k));
  const cooling   = rotated.filter(k =>  isVtKeyCoolingDown(k));
  return [...available, ...cooling];
}

/** How many keys are currently available (not in cooldown). */
function getVtAvailableKeyCount() {
  return getVtKeys().filter(k => !isVtKeyCoolingDown(k)).length;
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
  getVtAvailableKeyCount,
  markVtKeyRateLimited,
  isVtKeyCoolingDown,
  isVtRateLimited,
  isVtBadKey,
  shouldTryNextVtKey,
};
