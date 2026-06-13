'use strict';
const { httpGet } = require('./_http');
const { requireAuth } = require('./_auth');
const { logApiUsage } = require('./_usage');

const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

// Pick the best available CVSS metric (v3.1 > v3.0 > v2). NVD nests baseScore in
// cvssData; v2 keeps baseSeverity on the metric wrapper, v3 inside cvssData.
function pickCvss(metrics) {
  if (!metrics) return null;
  const order = [
    ['cvssMetricV31', '3.1'],
    ['cvssMetricV30', '3.0'],
    ['cvssMetricV2', '2.0'],
  ];
  for (const [key, ver] of order) {
    const arr = metrics[key];
    if (Array.isArray(arr) && arr.length) {
      const d = arr[0].cvssData || {};
      return {
        version: d.version || ver,
        score: typeof d.baseScore === 'number' ? d.baseScore : null,
        severity: d.baseSeverity || arr[0].baseSeverity || null,
        vector: d.vectorString || null,
      };
    }
  }
  return null;
}

// ── CVE / NVD lookup ──
// ?id=CVE-YYYY-NNNN  → exact CVE; ?q=keyword → keyword search (max 20).
// Optional NVD_API_KEY raises the rate limit.
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const id = String(req.query.id || '').trim();
  const q = String(req.query.q || '').trim();
  if (!id && !q) return res.status(400).json({ error: 'Provide ?id=CVE-YYYY-NNNN or ?q=keyword.' });
  if (id && !CVE_ID_RE.test(id))
    return res.status(400).json({ error: 'Invalid CVE ID format (expected CVE-YYYY-NNNN).' });

  const params = id
    ? `cveId=${encodeURIComponent(id.toUpperCase())}`
    : `keywordSearch=${encodeURIComponent(q)}&resultsPerPage=20`;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`;

  const headers = { Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' };
  const nvdKeyPrefix = process.env.NVD_API_KEY ? process.env.NVD_API_KEY.slice(0, 8) + '…' : null;
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;

  try {
    const { status, data } = await httpGet(url, headers, { timeout: 12000 });
    logApiUsage(req, { service: 'NVD', outcome: status === 200 || status === 404 ? 'ok' : 'error', api_key: nvdKeyPrefix }).catch(() => {});
    if (status === 404) return res.status(200).json({ ok: true, query: id || q, total: 0, results: [] });
    if (status !== 200) return res.status(502).json({ error: `NVD upstream error (HTTP ${status}).` });

    const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    const results = vulns.map((v) => {
      const cve = v.cve || {};
      const desc = (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '—';
      const refs = (cve.references || []).map((r) => r.url).filter(Boolean).slice(0, 8);
      return {
        id: cve.id,
        description: desc,
        cvss: pickCvss(cve.metrics),
        published: cve.published || null,
        lastModified: cve.lastModified || null,
        references: refs,
      };
    });
    return res.status(200).json({ ok: true, query: id || q, total: data.totalResults ?? results.length, results });
  } catch (e) {
    logApiUsage(req, { service: 'NVD', outcome: 'error', api_key: nvdKeyPrefix }).catch(() => {});
    return res.status(502).json({ error: `Cannot reach NVD: ${e.message}` });
  }
};

// Exposed for unit tests.
module.exports.pickCvss = pickCvss;
