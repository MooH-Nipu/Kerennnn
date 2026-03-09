const https = require('https');

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

// ── Strip URL → extract bare IOC ──────────────────────────────────────────
function extractIOC(raw) {
  let s = raw.trim();

  // Remove surrounding brackets/quotes (defanged IOCs like hxxps[://]evil[.]com)
  s = s.replace(/^\[|\]$/g, '');

  // Defang: hxxp/hxxps → http/https, [.] → .
  s = s.replace(/^hxxps?/i, 'https');
  s = s.replace(/\[\.\]/g, '.').replace(/\(dot\)/gi, '.');

  // If it looks like a URL, parse out just the hostname
  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      s = u.hostname;
    } catch {
      // fallback: strip scheme and take up to first /
      s = s.replace(/^https?:\/\//i, '').split('/')[0];
    }
  }

  // Strip trailing dot (FQDN), port, path, query
  s = s.split('/')[0].split('?')[0].split('#')[0];
  // Remove port if present (e.g. evil.com:8080 or 1.2.3.4:443)
  s = s.replace(/:(\d+)$/, '');
  // Strip trailing dot
  s = s.replace(/\.$/, '');

  return s.toLowerCase();
}

// ── Detect IOC type ───────────────────────────────────────────────────────
function detectType(s) {
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ip';
  // IPv6 (simplified check)
  if (/^[0-9a-f:]{3,39}$/.test(s) && s.includes(':') && s.split(':').length >= 3) return 'ip';
  // Hash (MD5/SHA-1/SHA-256/SHA-512 etc.)
  if (/^[0-9a-f]+$/.test(s) && [32, 40, 56, 64, 96, 128].includes(s.length)) return 'hash';
  // Domain — must have at least one dot and valid chars
  if (/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/.test(s)) return 'domain';
  return null;
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

  // ── Try each key, failover on 429 ─────────────
  for (let i = 0; i < apiKeys.length; i++) {
    try {
      const { status, data } = await httpsGet(vtUrl, {
        'x-apikey': apiKeys[i],
        'Accept':   'application/json',
        'User-Agent': 'SOC-Toolbox/1.0',
      });

      if (status === 429) continue; // try next key

      // Inject meta so frontend knows cleaned IOC + type
      if (status === 200 && data.data) {
        data._meta = { type, ioc, original: rawIoc };
      }

      if (status === 200) res.setHeader('X-VT-Key-Used', `key-${i+1}-of-${apiKeys.length}`);
      return res.status(status).json(data);

    } catch (err) {
      continue;
    }
  }

  return res.status(429).json({
    error: { message: `All ${apiKeys.length} API key(s) are rate limited. Try again later.` }
  });
};