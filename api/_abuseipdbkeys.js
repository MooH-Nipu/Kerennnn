'use strict';

/**
 * Collects AbuseIPDB API keys from the environment for quota-overflow rotation.
 * ABUSEIPDB_API_KEY plus any numbered ABUSEIPDB_API_KEY_N entries.
 */
function getAbuseIPDBKeys() {
  const seen = new Set();
  const keys = [];
  const add = (raw) => {
    const key = typeof raw === 'string' ? raw.trim() : '';
    if (key && !seen.has(key)) { seen.add(key); keys.push(key); }
  };
  add(process.env.ABUSEIPDB_API_KEY);
  Object.keys(process.env)
    .map((name) => ({ name, match: /^ABUSEIPDB_API_KEY_(\d+)$/.exec(name) }))
    .filter(({ match }) => match && Number(match[1]) >= 2)
    .sort((a, b) => Number(a.match[1]) - Number(b.match[1]))
    .forEach(({ name }) => add(process.env[name]));
  return keys;
}

module.exports = { getAbuseIPDBKeys };
