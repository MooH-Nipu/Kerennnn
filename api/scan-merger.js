const { createClient } = require('@supabase/supabase-js');
const { normalizeIpLine } = require('./_ioc');

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
      const saved = [];

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

        const { data: existing, error: selErr } = await supabase
          .from('merger_scanned_ips')
          .select('payload')
          .eq('ip', ip)
          .maybeSingle();

        if (selErr) {
          errors.push({ index: i, ip, reason: selErr.message || String(selErr) });
          continue;
        }

        const base = existing && existing.payload && typeof existing.payload === 'object'
          ? { ...existing.payload }
          : {};

        const patch = { ...row };
        delete patch.ip;
        const merged = { ...base, ...patch, ioc: ip };

        const { error: upErr } = await supabase
          .from('merger_scanned_ips')
          .upsert(
            { ip, payload: merged, updated_at: new Date().toISOString() },
            { onConflict: 'ip' }
          );

        if (upErr) {
          errors.push({ index: i, ip, reason: upErr.message || String(upErr) });
        } else {
          saved.push(ip);
        }
      }

      return res.status(200).json({ ok: true, saved, errors, savedCount: saved.length, errorCount: errors.length });
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
