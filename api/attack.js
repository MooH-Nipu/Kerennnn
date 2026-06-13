'use strict';
const { httpGetText } = require('./_http');
const { requireAuth } = require('./_auth');
const { logApiUsage } = require('./_usage');

// ── MITRE ATT&CK (Enterprise) technique lookup ──
// The SPA can't fetch MITRE directly (CSP connect-src 'self'), so we proxy it:
// fetch the STIX bundle once, reduce it to a lean technique index, and cache that
// in module memory (warm-instance) with a 7-day TTL. Searching is then in-memory.
const BUNDLE_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TECHNIQUE_ID_RE = /^t\d{4}(\.\d{3})?$/i;

let _cache = null; // { techniques: [...], builtAt: number }
let _building = null; // in-flight build promise (dedupe concurrent cold starts)

function reduceBundle(bundle) {
  const objects = Array.isArray(bundle && bundle.objects) ? bundle.objects : [];
  const techniques = [];
  for (const o of objects) {
    if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
    const ext = (o.external_references || []).find((r) => r.source_name === 'mitre-attack');
    const id = ext && ext.external_id;
    if (!id) continue;
    const tactics = (o.kill_chain_phases || [])
      .filter((k) => k.kill_chain_name === 'mitre-attack')
      .map((k) => k.phase_name);
    techniques.push({
      id,
      name: o.name || '—',
      description: (o.description || '').slice(0, 1500),
      tactics,
      platforms: o.x_mitre_platforms || [],
      detection: (o.x_mitre_detection || '').slice(0, 1500),
      isSubtechnique: !!o.x_mitre_is_subtechnique,
      url: (ext && ext.url) || `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
    });
  }
  return techniques;
}

async function getTechniques() {
  if (_cache && Date.now() - _cache.builtAt < CACHE_TTL_MS) return _cache.techniques;
  if (_building) return _building;
  _building = (async () => {
    const { status, text } = await httpGetText(
      BUNDLE_URL,
      { 'User-Agent': 'Charlie-kerennnn/1.0', Accept: 'application/json' },
      { timeout: 30000 }
    );
    if (status !== 200) throw new Error(`ATT&CK bundle HTTP ${status}`);
    const techniques = reduceBundle(JSON.parse(text));
    if (!techniques.length) throw new Error('ATT&CK bundle contained no techniques');
    _cache = { techniques, builtAt: Date.now() };
    return techniques;
  })();
  try {
    return await _building;
  } finally {
    _building = null;
  }
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const q = String(req.query.q || '').trim();
  if (!q) return res.status(400).json({ error: 'Provide ?q=<technique id or keyword>.' });

  let techniques;
  try {
    techniques = await getTechniques();
  } catch (e) {
    logApiUsage(req, { service: 'ATT&CK', outcome: 'error' }).catch(() => {});
    return res.status(502).json({ error: `Cannot load ATT&CK data: ${e.message}` });
  }
  logApiUsage(req, { service: 'ATT&CK', outcome: 'ok' }).catch(() => {});

  const term = q.toLowerCase();
  let results;
  if (TECHNIQUE_ID_RE.test(q)) {
    const idUpper = q.toUpperCase();
    // Exact technique + its sub-techniques (e.g. T1059 → T1059.001…).
    results = techniques.filter(
      (t) => t.id.toUpperCase() === idUpper || t.id.toUpperCase().startsWith(idUpper + '.')
    );
  } else {
    results = techniques.filter(
      (t) =>
        t.id.toLowerCase().includes(term) ||
        t.name.toLowerCase().includes(term) ||
        t.description.toLowerCase().includes(term)
    );
    // Rank name matches ahead of description-only matches.
    results.sort((a, b) => {
      const an = a.name.toLowerCase().includes(term) ? 0 : 1;
      const bn = b.name.toLowerCase().includes(term) ? 0 : 1;
      return an - bn || a.id.localeCompare(b.id);
    });
  }

  return res.status(200).json({ ok: true, query: q, total: results.length, results: results.slice(0, 40) });
};

// Exposed for unit tests.
module.exports.reduceBundle = reduceBundle;
