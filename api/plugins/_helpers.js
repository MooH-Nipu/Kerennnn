'use strict';
// Shared helpers used by plugins. Extracted from correlate.js verbatim.

function getTrustFactor(envKey, defaultValue = 1) {
  const raw = process.env[envKey];
  if (raw === undefined || raw === null || raw === '') return defaultValue;
  const n = Number.parseFloat(raw);
  if (!Number.isFinite(n) || n < 0) return defaultValue;
  return n;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Short, non-secret prefix of whichever API key served a call — for the usage
// log only (never store/return the full secret).
function kp(key) {
  return key ? String(key).slice(0, 8) + '…' : null;
}

// Substring match against commonly-abused hosting providers (case-insensitive).
const HIGH_RISK_HOSTERS = [
  'digitalocean', 'ovh', 'vultr', 'choopa', 'linode', 'akamai connected cloud',
  'hetzner', 'm247', 'quadranet', 'frantech', 'buyvm', 'worldstream',
  'nforce', 'cogent', 'leaseweb', 'datacamp', 'psychz', 'constant company',
  'serverius', 'host sailor', 'shock hosting', 'colocrossing', 'incognet',
];

function ispIsHighRiskHoster(isp) {
  if (!isp) return null;
  const lower = String(isp).toLowerCase();
  for (const needle of HIGH_RISK_HOSTERS) {
    if (lower.includes(needle)) return needle;
  }
  return null;
}

module.exports = { getTrustFactor, sleep, kp, HIGH_RISK_HOSTERS, ispIsHighRiskHoster };
