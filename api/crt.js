'use strict';
const { extractIOC, detectType } = require('./_ioc');
const { httpGet } = require('./_http');
const { requireAuth } = require('./_auth');

// ── Certificate Transparency history via crt.sh (free, no key) ──
// Reveals every SSL/TLS cert ever issued for a domain → subdomains + infra history.
// Proxied server-side (SPA CSP is connect-src 'self').
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const domain = extractIOC(req.query.domain || req.query.ioc);
  if (!domain || detectType(domain) !== 'domain')
    return res.status(400).json({ error: 'Certificate history supports domains only.' });

  try {
    const { status, data } = await httpGet(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      { Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' },
      { timeout: 15000 }
    );
    if (status !== 200 || !Array.isArray(data))
      return res.status(502).json({ error: `crt.sh upstream error (HTTP ${status}).` });

    // Dedupe certs; collect covered names (name_value is newline-separated SANs).
    const seen = new Set();
    const certs = [];
    for (const row of data) {
      const key = row.id || `${row.issuer_name}|${row.not_before}|${row.name_value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const names = String(row.name_value || '')
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      certs.push({
        issuer: row.issuer_name || '—',
        not_before: row.not_before || null,
        not_after: row.not_after || null,
        names: Array.from(new Set(names)).slice(0, 12),
      });
    }
    certs.sort((a, b) => String(b.not_before).localeCompare(String(a.not_before)));

    // Flattened unique subdomains across all certs — handy pivot list.
    const subdomains = Array.from(
      new Set(certs.flatMap((c) => c.names).filter((n) => n.endsWith(domain) && !n.startsWith('*')))
    ).sort();

    return res.status(200).json({
      ok: true,
      domain,
      total: certs.length,
      certs: certs.slice(0, 100),
      subdomains: subdomains.slice(0, 200),
    });
  } catch (e) {
    return res.status(502).json({ error: `Cannot reach crt.sh: ${e.message}` });
  }
};
