'use strict';
const { TIPlugin } = require('./_base');
const { getTrustFactor, sleep, kp } = require('./_helpers');
const { httpGet, httpPost } = require('../_http');
const { isFreshCacheRow } = require('../_vt-cache-policy');

// ── URLScan.io (weight 0.20, domain only) ────────────────────────────────
// Two paths, cheapest first:
//   1. Historical search hit that is still inside the shared cache TTL
//      (1 request for search + 1 for the result, ~0.7-2s). Most public
//      infrastructure has already been scanned by someone.
//   2. Active submit + poll (8-33s) — everything else, including any domain
//      whose last public scan is older than the TTL, so evidence freshness is
//      unchanged from the previous implementation.
// Tier 1 honours `opts.refresh`, so ?refresh=1 still forces a live scan.
// Runs concurrently in Promise.all so it doesn't block other sources.

// URLScan verdicts.overall → our verdict vocabulary.
function verdictFrom(overall) {
  const score = overall?.score ?? 0;
  if (overall?.malicious) return { verdict: 'malicious', score: Math.min(100, score) };
  return { verdict: score > 50 ? 'suspicious' : 'clean', score: Math.min(100, score) };
}

// Builds the plugin result from a search-API row or a result-API body. Both
// expose the same fields under `verdicts`/`page`/`task`.
function buildResult(apiKey, src) {
  const overall = src.verdicts?.overall;
  const { verdict, score } = verdictFrom(overall);
  const tags = (overall?.tags || []).slice(0, 4);
  const uuid = src.task?.uuid;
  return {
    source: 'URLScan.io',
    verdict,
    score,
    keyPrefix: kp(apiKey),
    weight: 0.20 * getTrustFactor('TRUST_URLSCAN'),
    meta: {
      Title: (src.page?.title || '—').slice(0, 60),
      'Status Code': src.page?.status || '—',
      Tags: tags.join(', ') || '—',
      Screenshot: src.screenshot || src.task?.screenshotURL || (uuid ? `https://urlscan.io/screenshots/${uuid}.png` : '—'),
    },
    link: src.result || (uuid ? `https://urlscan.io/result/${uuid}/` : 'https://urlscan.io/'),
  };
}

// Tier 1: newest result for this exact domain, in two short requests.
// `task.domain:"<d>"` is the exact-domain predicate — `page.domain:<d>` matches
// loosely (example.com returns sosnina.icu) and must NOT be used here.
async function recentPublicScan(apiKey, domain) {
  const q = `task.domain:"${domain.replace(/"/g, '')}"`;
  const searchUrl = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=1`;
  const { status, data } = await httpGet(
    searchUrl,
    { 'API-Key': apiKey, Accept: 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' },
    { timeout: 8000 }
  );
  if (status !== 200) return null;

  const row = Array.isArray(data?.results) ? data.results[0] : null;
  const uuid = row?.task?.uuid;
  const observedAt = row?.task?.time;
  if (!uuid || !Number.isFinite(Date.parse(observedAt || ''))) return null;

  // Search rows carry task/stats/page but no verdicts; the verdict lives behind
  // /result/<uuid>/. Check freshness before paying for the second request.
  const fresh = isFreshCacheRow({
    last_scanned_at: observedAt,
    first_scanned_at: observedAt,
    // Malicious evidence keeps longest, matching the shared TTL policy.
    vt_verdict: (row.task?.tags || []).some(t => /malicious|phishing|possiblethreat/i.test(t))
      ? 'malicious'
      : 'clean',
  });
  if (!fresh) return null;

  const { status: rStatus, data: body } = await httpGet(
    `https://urlscan.io/api/v1/result/${uuid}/`,
    { 'API-Key': apiKey, Accept: 'application/json' },
    { timeout: 8000 }
  );
  if (rStatus !== 200 || body?.verdicts?.overall?.hasVerdicts === false) return null;
  return body;
}

class URLScanPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'URLScan.io';
    this.supportedTypes = ['domain'];
    // Tier 2 submit + poll dominates: up to ~45s.
    this.timeoutMs = 45_000;
  }

  isAvailable() {
    return !!process.env.URLSCAN_API_KEY;
  }

  async check(domain, _type, opts = {}) {
    const apiKey = process.env.URLSCAN_API_KEY;
    if (!apiKey) return { source: 'URLScan.io', skipped: true, reason: 'No API key' };

    // ── Tier 1: still-fresh public evidence, no submit ─────────────────────
    if (!opts.refresh) {
      try {
        const cached = await recentPublicScan(apiKey, domain);
        if (cached) return buildResult(apiKey, cached);
      } catch {
        // Search is best-effort; fall through to the active scan.
      }
    }

    // ── Tier 2: active scan, submit + poll ────────────────────────────────
    try {
      const submitBody = JSON.stringify({ url: `https://${domain}`, visibility: 'unlisted' });
      const { status: submitStatus, data: submitData } = await httpPost(
        'https://urlscan.io/api/v1/scan/',
        submitBody,
        {
          'API-Key': apiKey,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(submitBody),
          Accept: 'application/json',
          'User-Agent': 'Charlie-kerennnn/1.0',
        },
        { timeout: 10000 }
      );
      if (submitStatus !== 200)
        return { source: 'URLScan.io', error: `Submit failed: HTTP ${submitStatus}` };

      const uuid = submitData?.uuid;
      if (!uuid) return { source: 'URLScan.io', error: 'No scan UUID returned' };

      // Scans complete in 5-15s; poll up to 6 times at 5s intervals after initial 8s wait.
      await sleep(8000);
      let result = null;
      for (let attempt = 0; attempt < 6; attempt++) {
        try {
          const { status, data } = await httpGet(
            `https://urlscan.io/api/v1/result/${uuid}/`,
            { 'API-Key': apiKey, Accept: 'application/json' },
            { timeout: 8000 }
          );
          // 200 = result ready; also accept if verdicts exist (partial data)
          if (status === 200 && data?.verdicts?.overall?.hasVerdicts !== false) { result = data; break; }
        } catch { /* not ready yet */ }
        if (attempt < 5) await sleep(5000);
      }

      if (!result) return { source: 'URLScan.io', error: 'Scan result not ready (timed out)' };
      return buildResult(apiKey, result);
    } catch (e) {
      return { source: 'URLScan.io', error: `Cannot access URLScan.io: ${e.message}` };
    }
  }
}

module.exports = { URLScanPlugin };
