const https = require('https');

// Load all keys: VT_API_KEY, VT_API_KEY_2, VT_API_KEY_3, ... up to 10
function getApiKeys() {
  const keys = [];
  const k1 = process.env.VT_API_KEY;
  if (k1) keys.push(k1);
  for (let i = 2; i <= 10; i++) {
    const k = process.env[`VT_API_KEY_${i}`];
    if (k) keys.push(k);
  }
  return keys;
}

function httpsGet(url, headers) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          reject(new Error('Failed to parse VT response: ' + body.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const apiKeys = getApiKeys();

  // ── Health check ──────────────────────────────
  if (req.query.health === '1') {
    return res.status(200).json({
      ok: true,
      totalKeys: apiKeys.length,
      keys: apiKeys.map((k, i) => ({ index: i + 1, prefix: k.slice(0, 6) + '...' })),
      node: process.version,
    });
  }

  // ── Validation ────────────────────────────────
  if (apiKeys.length === 0) {
    return res.status(500).json({ error: { message: 'No API keys configured. Set VT_API_KEY in environment variables.' } });
  }

  const { type, ioc } = req.query;
  if (!type || !ioc) {
    return res.status(400).json({ error: { message: 'Missing ?type= or ?ioc= param.' } });
  }

  const urlMap = {
    hash: `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
    ip:   `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
  };

  const vtUrl = urlMap[type];
  if (!vtUrl) {
    return res.status(400).json({ error: { message: `Invalid type "${type}". Use hash or ip.` } });
  }

  // ── Try each key, failover on 429 ─────────────
  let lastError = null;

  for (let i = 0; i < apiKeys.length; i++) {
    try {
      const { status, data } = await httpsGet(vtUrl, {
        'x-apikey': apiKeys[i],
        'Accept': 'application/json',
        'User-Agent': 'SOC-Toolbox/1.0',
      });

      if (status === 429) {
        // Rate limited — try next key
        lastError = { status: 429, message: `Key ${i + 1} rate limited, trying next...` };
        continue;
      }

      // Success or non-quota error — return as-is
      // Attach which key index was used (for debugging, no sensitive info)
      if (status === 200) {
        res.setHeader('X-VT-Key-Used', `key-${i + 1}-of-${apiKeys.length}`);
      }
      return res.status(status).json(data);

    } catch (err) {
      lastError = { status: 500, message: err.message };
      continue;
    }
  }

  // All keys exhausted
  return res.status(429).json({
    error: {
      message: `All ${apiKeys.length} API key(s) are rate limited. Try again later.`
    }
  });
};