'use strict';

/**
 * Collects AbuseIPDB API keys from the environment for quota-overflow rotation.
 * ABUSEIPDB_API_KEY plus optional ABUSEIPDB_API_KEY_2 … ABUSEIPDB_API_KEY_10.
 */
function getAbuseIPDBKeys() {
  const keys = [];
  const k1 = process.env.ABUSEIPDB_API_KEY;
  if (k1) keys.push(k1);
  for (let i = 2; i <= 10; i++) {
    const k = process.env[`ABUSEIPDB_API_KEY_${i}`];
    if (k) keys.push(k);
  }
  return keys;
}

module.exports = { getAbuseIPDBKeys };
