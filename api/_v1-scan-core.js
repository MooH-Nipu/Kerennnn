'use strict';
const { extractIOC, detectType } = require('./_ioc');
const { labelFromConfidence, vtStats } = require('./_verdict');

const MAX_BATCH = Math.min(Number.parseInt(process.env.API_MAX_IOCS_PER_REQUEST, 10) || 10, 25);
const CONCURRENCY = 2;

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next++;
      out[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function sourceRow(source) {
  return {
    source: source.source,
    verdict: source.verdict ?? null,
    score: typeof source.score === 'number' ? source.score : null,
    weight: typeof source.weight === 'number' ? source.weight : null,
    error: source.error ?? null,
  };
}

/**
 * Scans normalized IOCs through the existing vt + correlate handlers.
 * `invoke` is injected so tests never touch the network.
 */
async function scanBatch({ rawIocs, allowedTypes, auth, invoke, vtHandler, correlateHandler }) {
  const seen = new Set();
  const queue = [];
  const errors = [];

  for (const raw of rawIocs) {
    const ioc = extractIOC(raw);
    const type = detectType(ioc);
    if (!type) { errors.push({ ioc: String(raw), error: 'UNRECOGNIZED_IOC' }); continue; }
    if (!allowedTypes.includes(type)) { errors.push({ ioc, error: 'TYPE_NOT_ALLOWED' }); continue; }
    if (seen.has(ioc)) continue;
    seen.add(ioc);
    queue.push({ ioc, type });
  }

  const results = await mapLimit(queue, CONCURRENCY, async ({ ioc, type }) => {
    const vt = await invoke(vtHandler, { query: { ioc }, auth });
    const corr = await invoke(correlateHandler, { query: { ioc }, auth });

    if (vt.status !== 200) {
      errors.push({ ioc, error: (vt.body && vt.body.error) || { code: 'VT_FAILED', message: `HTTP ${vt.status}` } });
    }
    if (corr.status !== 200) {
      errors.push({ ioc, error: (corr.body && corr.body.error) || { code: 'CORRELATE_FAILED', message: `HTTP ${corr.status}` } });
    }

    const stats = vtStats(vt.body);
    const payload = corr.status === 200 ? corr.body : null;
    const sources = Array.isArray(payload?.sources) ? payload.sources.filter(s => !s.skipped).map(sourceRow) : [];

    return {
      ioc,
      type,
      verdict: labelFromConfidence(payload?.confidence),
      confidence: typeof payload?.confidence === 'number' ? payload.confidence : null,
      vt: stats,
      sources,
      riskFactors: Array.isArray(payload?.riskFactors) ? payload.riskFactors : [],
      cached: Boolean(vt.body && vt.body._meta && vt.body._meta.cache && vt.body._meta.cache.fromCache),
    };
  });

  return { results, errors };
}

module.exports = { scanBatch, mapLimit, MAX_BATCH, CONCURRENCY };
