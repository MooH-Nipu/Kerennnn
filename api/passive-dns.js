'use strict';
const { extractIOC, detectType } = require('./_ioc');
const { httpGetText } = require('./_http');
const { requireAuth } = require('./_auth');

// ── Passive DNS via HackerTarget (free, no key; ~50 queries/day per source IP) ──
// domain → hostsearch (returns "subdomain,ip" CSV lines)
// ip     → reverseiplookup (returns one hostname per line)
// Proxied server-side because the SPA's CSP is connect-src 'self'.
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const ioc = extractIOC(req.query.ioc);
  const type = detectType(ioc);
  if (!ioc || (type !== 'ip' && type !== 'domain'))
    return res.status(400).json({ error: 'Passive DNS supports IP or domain only.' });

  const url = type === 'domain'
    ? `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(ioc)}`
    : `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ioc)}`;

  try {
    const { status, text } = await httpGetText(
      url,
      { 'User-Agent': 'Charlie-kerennnn/1.0', Accept: 'text/plain' },
      { timeout: 10000 }
    );
    const body = String(text || '').trim();
    if (status !== 200)
      return res.status(502).json({ error: `Passive DNS upstream error (HTTP ${status}).` });

    // HackerTarget reports problems as a plain-text 200 message (no commas / known phrases).
    if (!body || (!body.includes(',') && /API count exceeded|error|no records|invalid|not found/i.test(body)))
      return res.status(200).json({ ok: true, ioc, type, records: [], note: body.slice(0, 160) });

    const records = body
      .split('\n')
      .map((line) => {
        const [host, ip] = line.split(',');
        return type === 'domain'
          ? { host: (host || '').trim(), ip: (ip || '').trim() }
          : { host: (host || '').trim() };
      })
      .filter((r) => r.host);

    return res.status(200).json({ ok: true, ioc, type, records: records.slice(0, 200) });
  } catch (e) {
    return res.status(502).json({ error: `Cannot reach Passive DNS provider: ${e.message}` });
  }
};
