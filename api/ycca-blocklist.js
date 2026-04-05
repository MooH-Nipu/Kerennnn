const { createClient } = require('@supabase/supabase-js');
const { normalizeIpLine } = require('./_ioc');

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => {
      try {
        resolve(b ? JSON.parse(b) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function getPasswordFromRequest(req) {
  const auth = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (m) return m[1].trim();
  const h = req.headers['x-ycca-password'];
  if (h) return String(h).trim();
  return null;
}

function checkYccaPassword(pw) {
  const expected = process.env.YCCA_PASSWORD || '';
  if (!expected) return false;
  return pw === expected;
}

function getSupabase() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-YCCA-Password');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const password = getPasswordFromRequest(req);
  if (!password || !checkYccaPassword(password)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({ error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).' });
  }

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('ycca_blocked_ips')
      .select('ip, created_at')
      .order('ip', { ascending: true });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ items: data || [] });
  }

  if (req.method === 'POST') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }

    const rawList = Array.isArray(body.ips) ? body.ips : [];
    const valid = [];
    const skipped = [];

    for (const line of rawList) {
      const ip = normalizeIpLine(String(line ?? ''));
      if (ip) valid.push(ip);
      else if (String(line ?? '').trim()) skipped.push(String(line).trim());
    }

    const unique = [...new Set(valid)];
    let inserted = 0;
    let duplicate = 0;

    for (const ip of unique) {
      const { error } = await supabase.from('ycca_blocked_ips').insert({ ip });
      if (error) {
        const msg = `${error.code || ''} ${error.message || ''} ${error.details || ''}`;
        if (error.code === '23505' || /duplicate|unique|already exists/i.test(msg)) duplicate++;
        else return res.status(500).json({ error: error.message });
      } else {
        inserted++;
      }
    }

    return res.status(200).json({
      inserted,
      duplicate,
      skippedNonIp: skipped,
      totalRequested: rawList.length,
    });
  }

  if (req.method === 'DELETE') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }

    const rawList = Array.isArray(body.ips) ? body.ips : [];
    const ips = [];
    for (const line of rawList) {
      const ip = normalizeIpLine(String(line ?? ''));
      if (ip) ips.push(ip);
    }
    const unique = [...new Set(ips)];
    if (!unique.length) {
      return res.status(400).json({ error: 'No valid IPs to delete.' });
    }

    const { error } = await supabase.from('ycca_blocked_ips').delete().in('ip', unique);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ deleted: unique.length });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
