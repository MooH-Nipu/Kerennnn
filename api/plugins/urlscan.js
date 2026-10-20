'use strict';
const { TIPlugin } = require('./_base');
const { getTrustFactor, sleep, kp } = require('./_helpers');
const { httpGet, httpPost } = require('../_http');

// ── URLScan.io (weight 0.20, domain only) ────────────────────────────────
// Two-step: POST submit → poll GET result. Adds ~10-15s latency for domain IOCs.
// Runs concurrently in Promise.all so it doesn't block other sources.

class URLScanPlugin extends TIPlugin {
  constructor() {
    super();
    this.name = 'URLScan.io';
    this.supportedTypes = ['domain'];
    // Active browser scan: submit + wait + poll takes up to ~45s.
    this.timeoutMs = 45_000;
  }

  isAvailable() {
    return !!process.env.URLSCAN_API_KEY;
  }

  async check(domain) {
    const apiKey = process.env.URLSCAN_API_KEY;
    if (!apiKey) return { source: 'URLScan.io', skipped: true, reason: 'No API key' };
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

      const verdicts = result.verdicts?.overall;
      const malicious = verdicts?.malicious ?? false;
      const overallScore = verdicts?.score ?? 0;
      const tags = (verdicts?.tags || []).slice(0, 4);

      const verdict = malicious ? 'malicious' : overallScore > 50 ? 'suspicious' : 'clean';

      return {
        source: 'URLScan.io',
        verdict,
        score: Math.min(100, overallScore),
        keyPrefix: kp(apiKey),
        weight: 0.20 * getTrustFactor('TRUST_URLSCAN'),
        meta: {
          Title: (result.page?.title || '—').slice(0, 60),
          'Status Code': result.page?.status || '—',
          Tags: tags.join(', ') || '—',
          Screenshot: result.screenshot || result.task?.screenshotURL || `https://urlscan.io/screenshots/${uuid}.png`,
        },
        link: result.result || `https://urlscan.io/result/${uuid}/`,
      };
    } catch (e) {
      return { source: 'URLScan.io', error: `Cannot access URLScan.io: ${e.message}` };
    }
  }
}

module.exports = { URLScanPlugin };
