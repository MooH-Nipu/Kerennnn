const https = require('https');
const { extractIOC, detectType } = require('./_ioc');

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

  const { ioc: rawIoc } = req.query;
  if (!rawIoc) {
    return res.status(400).json({ error: { message: 'Missing ?ioc= param.' } });
  }

  // ── Clean + detect ────────────────────────────
  const ioc  = extractIOC(rawIoc);
  const type = detectType(ioc);

  if (!type) {
    return res.status(400).json({
      error: { message: `Cannot detect IOC type for: "${ioc}". Supports IP, domain, hash (MD5/SHA-1/SHA-256/SHA-512).` }
    });
  }

  const urlMap = {
    hash:   `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
    ip:     `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
    domain: `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`,
  };

  const vtUrl = urlMap[type];

  // Detect rate limit in response body (some APIs return 403/200 with quota message)
  function isRateLimitResponse(status, data) {
    if (status === 429) return true;
    const msg = (data?.error?.message || data?.message || '').toLowerCase();
    if (status === 403 && /quota|rate limit|too many|limit exceeded/.test(msg)) return true;
    if (status === 200 && data?.error && /quota|rate limit|too many/.test(msg)) return true;
    return false;
  }

  // ── Try each key in order; on 429/quota auto-switch to next key for this same request ──
  let lastError = null;
  let rateLimitedCount = 0;

  for (let i = 0; i < apiKeys.length; i++) {
    try {
      const { status, data } = await httpsGet(vtUrl, {
        'x-apikey': apiKeys[i],
        'Accept':   'application/json',
        'User-Agent': 'Charlie-kerennnn/1.0',
      });

      if (isRateLimitResponse(status, data)) {
        rateLimitedCount++;
        continue; // try next key immediately for this same IOC
      }

      // Inject meta so frontend knows cleaned IOC + type
      if (status === 200 && data.data) {
        data._meta = { type, ioc, original: rawIoc };
      }

      if (status === 200) res.setHeader('X-VT-Key-Used', `key-${i + 1}-of-${apiKeys.length}`);
      return res.status(status).json(data);

    } catch (err) {
      lastError = err;
      continue;
    }
  }

  // All keys failed: distinguish rate limit vs access error
  if (rateLimitedCount === apiKeys.length) {
    return res.status(429).json({
      error: { message: `All ${apiKeys.length} API key(s) are rate limited. Try again later.` }
    });
  }

  // Cannot access VirusTotal (network, timeout, parse error, etc.)
  const msg = lastError?.message || 'Unknown error';
  return res.status(503).json({
    error: { message: `Cannot access VirusTotal: ${msg}` }
  });
};