const { createClient } = require('@supabase/supabase-js');
const { normalizeIpLine } = require('./_ioc');

/** ISO-8601 dengan offset WIB (+07:00) untuk kolom timestamptz (Postgres menyimpan momen absolut). */
function currentUpdatedAtIsoWib() {
  const d = new Date();
  const parts = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Asia/Jakarta',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).formatToParts(d);
  const t = (ty) => (parts.find((p) => p.type === ty) || {}).value || '';
  const y = t('year');
  const mo = t('month');
  const da = t('day');
  const h = t('hour');
  const mi = t('minute');
  const sec = t('second');
  if (y && mo && da) return `${y}-${mo}-${da}T${h || '00'}:${mi || '00'}:${sec || '00'}+07:00`;
  return new Date().toISOString();
}

function getSupabase() {
  const url = process.env.SUPABASE_URL || '';
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
  if (!url || !key) return null;
  return createClient(url, key);
}

function mergerPasswordOk(req) {
  const expected = process.env.MERGER_API_PASSWORD || '';
  if (!expected) return true;
  const got = req.headers['x-merger-password'];
  return typeof got === 'string' && got === expected;
}

async function readJsonBody(req) {
  if (req.body != null && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body;
  }
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 2e6) req.destroy(new Error('Body too large')); });
    req.on('end', () => {
      if (!raw.trim()) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Merger-Password');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!mergerPasswordOk(req)) {
    return res.status(401).json({ error: 'Invalid or missing X-Merger-Password header.' });
  }

  const supabase = getSupabase();
  if (!supabase) {
    return res.status(503).json({
      error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).',
    });
  }

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase
        .from('merger_scanned_ips')
        .select('ip,payload,updated_at')
        .order('ip', { ascending: true });
      if (error) return res.status(500).json({ error: error.message || String(error) });
      return res.status(200).json({ items: data || [] });
    }

    if (req.method === 'POST') {
      let body;
      try {
        body = await readJsonBody(req);
      } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON body.' });
      }
      const items = body && Array.isArray(body.items) ? body.items : null;
      if (!items || !items.length) {
        return res.status(400).json({ error: 'Body must include { items: [ ... ] } with at least one object.' });
      }

      const errors = [];
      /** @type {Map<string, { indices: number[], mergedPatch: Record<string, unknown> }>} */
      const byIp = new Map();

      for (let i = 0; i < items.length; i++) {
        const row = items[i];
        if (!row || typeof row !== 'object') {
          errors.push({ index: i, reason: 'not an object' });
          continue;
        }
        const ip = normalizeIpLine(row.ip != null ? row.ip : row.ioc);
        if (!ip) {
          errors.push({ index: i, reason: 'missing or invalid ip/ioc' });
          continue;
        }
        const patch = { ...row };
        delete patch.ip;
        delete patch.ioc;
        if (!byIp.has(ip)) {
          byIp.set(ip, { indices: [i], mergedPatch: { ...patch } });
        } else {
          const entry = byIp.get(ip);
          entry.indices.push(i);
          entry.mergedPatch = { ...entry.mergedPatch, ...patch };
        }
      }

      const saved = [];
      const skipped = [];

      for (const [ip, { mergedPatch }] of byIp) {
        const { data: existing, error: selErr } = await supabase
          .from('merger_scanned_ips')
          .select('ip')
          .eq('ip', ip)
          .maybeSingle();

        if (selErr) {
          errors.push({ ip, reason: selErr.message || String(selErr) });
          continue;
        }

        if (existing != null && existing.ip) {
          skipped.push(ip);
          continue;
        }

        const merged = { ...mergedPatch, ioc: ip };

        const { error: insErr } = await supabase.from('merger_scanned_ips').insert({
          ip,
          payload: merged,
          updated_at: currentUpdatedAtIsoWib(),
        });

        if (insErr) {
          errors.push({ ip, reason: insErr.message || String(insErr) });
        } else {
          saved.push(ip);
        }
      }

      return res.status(200).json({
        ok: true,
        saved,
        skipped,
        errors,
        savedCount: saved.length,
        skippedCount: skipped.length,
        errorCount: errors.length,
        uniqueIpCount: byIp.size,
      });
    }

    if (req.method === 'DELETE') {
      const q = req.query || {};
      let ip = typeof q.ip === 'string' ? q.ip.trim() : '';
      if (!ip) {
        let body = {};
        try {
          body = await readJsonBody(req);
        } catch (e) {
          return res.status(400).json({ error: 'Invalid JSON body.' });
        }
        ip = (body.ip != null ? String(body.ip) : '').trim();
      }
      const norm = normalizeIpLine(ip);
      if (!norm) {
        return res.status(400).json({ error: 'Missing or invalid ip (query ?ip= or JSON { ip }).' });
      }

      const { error } = await supabase.from('merger_scanned_ips').delete().eq('ip', norm);
      if (error) return res.status(500).json({ error: error.message || String(error) });
      return res.status(200).json({ ok: true, deleted: norm });
    }

    res.setHeader('Allow', 'GET, POST, DELETE, OPTIONS');
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    return res.status(500).json({ error: e.message || String(e) });
  }
};
