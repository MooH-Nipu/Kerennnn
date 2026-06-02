'use strict';

/**
 * Collects VirusTotal API keys from the environment for round-robin rotation.
 * VT_API_KEY plus optional VT_API_KEY_2 … VT_API_KEY_10.
 */
function getVtKeys() {
  const keys = [];
  const k1 = process.env.VT_API_KEY;
  if (k1) keys.push(k1);
  for (let i = 2; i <= 10; i++) {
    const k = process.env[`VT_API_KEY_${i}`];
    if (k) keys.push(k);
  }
  return keys;
}

module.exports = { getVtKeys };
