'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/** Round-robin cursor — persists for the lifetime of a warm server instance. */
let rrIndex = 0;

/**
 * Per-key cooldown: maps key → Unix timestamp (ms) after which it is usable again.
 * Set by markVtKeyRateLimited() when a key returns 429. Checked by getVtKeysForRequest()
 * so the next request skips cooling-down keys instead of burning an attempt on them.
 */
const keyCooldownUntil = new Map();
const keyQuotaResetAt = new Map();

const VT_RATE_LIMIT_COOLDOWN_MS = 61_000; // 1s buffer over VT's 60s window

function keyId(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex');
}

function stateFile() {
  return process.env.VT_KEY_STATE_FILE || '';
}

function syncState() {
  const file = stateFile();
  if (!file) return;
  try {
    const state = JSON.parse(fs.readFileSync(file, 'utf8'));
    keyCooldownUntil.clear();
    keyQuotaResetAt.clear();
    for (const [id, until] of Object.entries(state.cooldown || {})) keyCooldownUntil.set(id, Number(until));
    for (const [id, until] of Object.entries(state.quota || {})) keyQuotaResetAt.set(id, until === null ? null : Number(until));
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn('[vt-keys] cannot read state:', error.message);
  }
}

function saveState() {
  const file = stateFile();
  if (!file) return;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const temp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temp, JSON.stringify({
      cooldown: Object.fromEntries(keyCooldownUntil),
      quota: Object.fromEntries(keyQuotaResetAt),
    }), { mode: 0o600 });
    fs.renameSync(temp, file);
  } catch (error) {
    console.warn('[vt-keys] cannot save state:', error.message);
  }
}

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
  if (!key) return;
  syncState();
  keyCooldownUntil.set(keyId(key), Date.now() + cooldownMs);
  saveState();
}

/** True if this key is still in its rate-limit cooldown window. */
function isVtKeyCoolingDown(key) {
  syncState();
  const id = keyId(key);
  const until = keyCooldownUntil.get(id);
  if (!until) return false;
  if (Date.now() >= until) {
    keyCooldownUntil.delete(id);
    saveState();
    return false;
  }
  return true;
}

/** QuotaExceededError is not a minute throttle; keep the key out until a known reset. */
function markVtKeyQuotaExceeded(key, resetAt = null) {
  if (!key) return;
  syncState();
  keyQuotaResetAt.set(keyId(key), resetAt === null ? null : Number(resetAt));
  saveState();
}

function getVtKeyQuotaResetAt(key) {
  syncState();
  const id = keyId(key);
  const resetAt = keyQuotaResetAt.get(id);
  if (!keyQuotaResetAt.has(id)) return null;
  if (resetAt !== null && Date.now() >= resetAt) {
    keyQuotaResetAt.delete(id);
    saveState();
    return null;
  }
  return resetAt;
}

function isVtKeyQuotaExceeded(key) {
  syncState();
  const id = keyId(key);
  getVtKeyQuotaResetAt(key);
  return keyQuotaResetAt.has(id);
}

/**
 * Keys for one outbound VT request, rotated so concurrent scans spread load.
 * Keys with exhausted quota are excluded until reset. Temporarily cooling keys
 * are skipped while another candidate is available.
 */
function getVtKeysForRequest() {
  const keys = getVtKeys().filter(k => !isVtKeyQuotaExceeded(k) && !isVtKeyCoolingDown(k));
  if (keys.length <= 1) return keys;

  const start = rrIndex % keys.length;
  rrIndex = (rrIndex + 1) % keys.length;
  return keys.slice(start).concat(keys.slice(0, start));
}

/** How many keys are currently available (not in cooldown). */
function getVtAvailableKeyCount() {
  return getVtKeys().filter(k => !isVtKeyCoolingDown(k) && !isVtKeyQuotaExceeded(k)).length;
}

function getNextVtQuotaResetAt() {
  const resets = getVtKeys().map(getVtKeyQuotaResetAt).filter(Boolean);
  return resets.length ? Math.min(...resets) : null;
}

function getNextVtCooldownAt() {
  syncState();
  const now = Date.now();
  const resets = getVtKeys().map(key => keyCooldownUntil.get(keyId(key))).filter(until => until > now);
  return resets.length ? Math.min(...resets) : null;
}

function vtErrorCode(data) {
  return data?.error?.code || '';
}

function isVtQuotaExceeded(_status, data) {
  return vtErrorCode(data) === 'QuotaExceededError';
}

function isVtTemporaryRateLimit(status, data) {
  if (isVtQuotaExceeded(status, data)) return false;
  return status === 429 || vtErrorCode(data) === 'TooManyRequestsError';
}

/** Daily/minute/monthly quota or per-minute burst limit (VT error codes). */
function isVtRateLimited(status, data) {
  return isVtQuotaExceeded(status, data) || isVtTemporaryRateLimit(status, data);
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
  getNextVtQuotaResetAt,
  getNextVtCooldownAt,
  markVtKeyRateLimited,
  markVtKeyQuotaExceeded,
  isVtKeyCoolingDown,
  isVtKeyQuotaExceeded,
  getVtKeyQuotaResetAt,
  isVtQuotaExceeded,
  isVtTemporaryRateLimit,
  isVtRateLimited,
  isVtBadKey,
  shouldTryNextVtKey,
};
