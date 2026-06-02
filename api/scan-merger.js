const { normalizeIpLine } = require('./_ioc');
const { requireRole, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

// Roles allowed to read/write the PAC Filter DB (mirrors PAC_ROLES in
// src/lib/permissions.ts). L2 is a second admin tier.
const PAC_ROLES = ['admin', 'pac', 'charlie', 'l2'];

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

function mergerPasswordOk(req) {
  const expected = process.env.MERGER_API_PASSWORD || '';
  if (!expected) return true;
  const got = req.headers['x-merger-password'];
  return typeof got === 'string' && got === expected;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Merger-Password');

  if (req.method === 'OPTIONS') return res.status(200).end();

  // Auth is mandatory and now role-gated server-side: only PAC-capable roles may
  // read/write the PAC Filter DB. Previously this was requireAuth only, so any
  // logged-in user (incl. l1) could reach the DB by calling the API directly.
  if (!requireRole(req, res, PAC_ROLES)) return;

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
      // PostgREST default max-rows per request is 1000 — page until exhausted.
      const pageSize = 1000;
      const items = [];
      let from = 0;
      for (;;) {
        const to = from + pageSize - 1;
        const { data, error } = await supabase
          .from('merger_scanned_ips')
          .select('ip,payload,updated_at')
          .order('ip', { ascending: true })
          .range(from, to);
        if (error) return serverError(res, error, 'scan-merger GET');
        const chunk = data || [];
        items.push(...chunk);
        if (chunk.length < pageSize) break;
        from += pageSize;
      }
      return res.status(200).json({ items });
    }

    if (req.method === 'POST') {
      let body;
      try {
        body = await readJsonBody(req);
      } catch {
        return res.status(400).json({ error: 'Invalid JSON body.' });
      }
      const items = body && Array.isArray(body.items) ? body.items : null;
      if (!items || !items.length) {
        return res
          .status(400)
          .json({ error: 'Body must include { items: [ ... ] } with at least one object.' });
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
      const ipList = [...byIp.keys()];
      const EXISTING_LOOKUP_CHUNK = 100;
      const existingSet = new Set();

      for (let li = 0; li < ipList.length; li += EXISTING_LOOKUP_CHUNK) {
        const slice = ipList.slice(li, li + EXISTING_LOOKUP_CHUNK);
        const { data: rows, error: selErr } = await supabase
          .from('merger_scanned_ips')
          .select('ip')
          .in('ip', slice);
        if (selErr) {
          return serverError(res, selErr, 'scan-merger lookup');
        }
        for (const row of rows || []) {
          if (row && row.ip) existingSet.add(row.ip);
        }
      }

      for (const [ip, { mergedPatch }] of byIp) {
        if (existingSet.has(ip)) {
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
      const queryIp = typeof q.ip === 'string' ? q.ip.trim() : '';

      if (queryIp) {
        const norm = normalizeIpLine(queryIp);
        if (!norm) {
          return res.status(400).json({ error: 'Invalid ip query parameter.' });
        }
        const { data: delRows, error } = await supabase
          .from('merger_scanned_ips')
          .delete()
          .eq('ip', norm)
          .select('ip');
        if (error) return serverError(res, error, 'scan-merger GET');
        const deletedCount = (delRows || []).length;
        return res.status(200).json({ ok: true, deleted: norm, deletedCount });
      }

      let body = {};
      try {
        body = await readJsonBody(req);
      } catch {
        return res.status(400).json({ error: 'Invalid JSON body.' });
      }

      if (body && Array.isArray(body.ips) && body.ips.length) {
        const DELETE_IN_CHUNK = 500;
        const MAX_IPS = 20000;
        const seen = new Set();
        const norms = [];
        for (const x of body.ips) {
          const n = normalizeIpLine(x != null ? String(x) : '');
          if (n && !seen.has(n)) {
            seen.add(n);
            norms.push(n);
          }
        }
        if (!norms.length) {
          return res.status(400).json({ error: 'No valid IPs in ips array.' });
        }
        if (norms.length > MAX_IPS) {
          return res.status(400).json({ error: `Too many IPs (max ${MAX_IPS} per request).` });
        }
        let deletedCount = 0;
        for (let i = 0; i < norms.length; i += DELETE_IN_CHUNK) {
          const slice = norms.slice(i, i + DELETE_IN_CHUNK);
          const { data: delRows, error } = await supabase
            .from('merger_scanned_ips')
            .delete()
            .in('ip', slice)
            .select('ip');
          if (error) return serverError(res, error, 'scan-merger GET');
          deletedCount += (delRows || []).length;
        }
        return res.status(200).json({
          ok: true,
          deletedCount,
          requested: norms.length,
        });
      }

      const ipSingle = (body.ip != null ? String(body.ip) : '').trim();
      const norm = normalizeIpLine(ipSingle);
      if (!norm) {
        return res.status(400).json({
          error: 'Missing or invalid ip (query ?ip=, JSON { ip }, or { ips: [...] }).',
        });
      }
      const { data: delRows, error } = await supabase
        .from('merger_scanned_ips')
        .delete()
        .eq('ip', norm)
        .select('ip');
      if (error) return serverError(res, error, 'scan-merger DELETE');
      const deletedCount = (delRows || []).length;
      return res.status(200).json({ ok: true, deleted: norm, deletedCount });
    }

    res.setHeader('Allow', 'GET, POST, DELETE, OPTIONS');
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    return serverError(res, e, 'scan-merger');
  }
};
