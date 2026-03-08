const https = require('https');

function httpsGet(url, headers) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch (e) {
          reject(new Error('Failed to parse VT response: ' + body.slice(0, 100)));
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

  const apiKey = process.env.VT_API_KEY;

  // ── Health check ──────────────────────────────
  if (req.url.includes('/api/health') || req.query.health === '1') {
    return res.status(200).json({
      ok: true,
      keySet: !!apiKey,
      keyPrefix: apiKey ? apiKey.slice(0, 6) + '...' : null,
      node: process.version,
    });
  }

  // ── Validation ────────────────────────────────
  if (!apiKey) {
    return res.status(500).json({ error: { message: 'VT_API_KEY not set in environment variables.' } });
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

  // ── Proxy to VT ──────────────────────────────
  try {
    const { status, data } = await httpsGet(vtUrl, {
      'x-apikey': apiKey,
      'Accept': 'application/json',
      'User-Agent': 'SOC-Toolbox/1.0',
    });
    return res.status(status).json(data);
  } catch (err) {
    return res.status(500).json({ error: { message: err.message } });
  }
};
