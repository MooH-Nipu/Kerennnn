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

/** Split array into fixed-size chunks (Supabase `.in()` URL limits). */
function chunkArray(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function fetchExistingIps(supabase, ips) {
  const existing = new Set();
  // Keep chunks small: long IPv6 + PostgREST `.in()` in query string can exceed proxy URL limits.
  for (const part of chunkArray(ips, 50)) {
    const { data, error } = await supabase.from('ycca_blocked_ips').select('ip').in('ip', part);
    if (error) throw new Error(error.message || JSON.stringify(error));
    for (const row of data || []) {
      if (row && row.ip) existing.add(row.ip);
    }
  }
  return existing;
}

async function insertIpsBatched(supabase, ips) {
  let inserted = 0;
  let duplicateFromRace = 0;
  for (const part of chunkArray(ips, 100)) {
    const rows = part.map((ip) => ({ ip }));
    const { error } = await supabase.from('ycca_blocked_ips').insert(rows);
    if (!error) {
      inserted += part.length;
      continue;
    }
    for (const ip of part) {
      const { error: e2 } = await supabase.from('ycca_blocked_ips').insert({ ip });
      if (e2) {
        const msg = `${e2.code || ''} ${e2.message || ''} ${e2.details || ''}`;
        if (e2.code === '23505' || /duplicate|unique|already exists/i.test(msg)) duplicateFromRace++;
        else throw new Error(e2.message);
      } else inserted++;
    }
  }
  return { inserted, duplicateFromRace };
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
    const pageSize = 1000;
    const items = [];
    let from = 0;
    for (;;) {
      const { data, error } = await supabase
        .from('ycca_blocked_ips')
        .select('ip, created_at')
        .order('ip', { ascending: true })
        .range(from, from + pageSize - 1);

      if (error) return res.status(500).json({ error: error.message || String(error) });
      const rows = data || [];
      items.push(...rows);
      if (rows.length < pageSize) break;
      from += pageSize;
    }
    return res.status(200).json({ items });
  }

  if (req.method === 'POST') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }

    const rawList = Array.isArray(body.ips) ? body.ips : [];

    /** Hanya cek keberadaan IP di DB (tanpa insert). */
    if (body.checkOnly === true || body.action === 'check') {
      const validNorm = [];
      for (const line of rawList) {
        const ip = normalizeIpLine(String(line ?? ''));
        if (ip) validNorm.push(ip);
      }
      const unique = [...new Set(validNorm)];
      let existing;
      try {
        existing = await fetchExistingIps(supabase, unique);
      } catch (e) {
        const msg = (e && e.message) || (typeof e === 'string' ? e : JSON.stringify(e));
        return res.status(500).json({ error: msg || String(e) });
      }

      const results = [];
      const skippedNonIp = [];
      for (const line of rawList) {
        const s = String(line ?? '').trim();
        if (!s) continue;
        const ip = normalizeIpLine(s);
        if (!ip) {
          skippedNonIp.push(s);
          results.push({ line: s, valid: false, exists: null });
        } else {
          results.push({ ip, line: s, valid: true, exists: existing.has(ip) });
        }
      }

      return res.status(200).json({
        results,
        skippedNonIp,
        totalLines: rawList.filter((x) => String(x ?? '').trim()).length,
      });
    }

    const valid = [];
    const skipped = [];

    for (const line of rawList) {
      const ip = normalizeIpLine(String(line ?? ''));
      if (ip) valid.push(ip);
      else if (String(line ?? '').trim()) skipped.push(String(line).trim());
    }

    const unique = [...new Set(valid)];
    let inserted = 0;
    let alreadyInDb = 0;
    let duplicateFromRace = 0;

    try {
      const existing = await fetchExistingIps(supabase, unique);
      const toInsert = unique.filter((ip) => !existing.has(ip));
      alreadyInDb = unique.length - toInsert.length;

      if (toInsert.length) {
        const ins = await insertIpsBatched(supabase, toInsert);
        inserted = ins.inserted;
        duplicateFromRace = ins.duplicateFromRace;
      }
    } catch (e) {
      const msg = (e && e.message) || (typeof e === 'string' ? e : JSON.stringify(e));
      return res.status(500).json({ error: msg || String(e) });
    }

    return res.status(200).json({
      inserted,
      alreadyInDb,
      /** @deprecated same as alreadyInDb; kept for older clients */
      duplicate: alreadyInDb + duplicateFromRace,
      duplicateFromRace,
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
