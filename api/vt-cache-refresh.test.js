const test = require('node:test');
const assert = require('node:assert/strict');

const modulePaths = [
  './_supabase', './_http', './_auth', './_vtkeys', './_usage',
  './_ipscans', './_scan-budget', './vt',
].map(require.resolve);

function mockModule(path, exports) {
  require.cache[path] = { id: path, filename: path, loaded: true, exports };
}

function response() {
  return {
    headers: {}, statusCode: null, body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
  };
}

test('stale clean cache refreshes to malicious and invalidates correlation', async () => {
  const originals = new Map(modulePaths.map(path => [path, require.cache[path]]));
  let vtCalls = 0;
  let updated = null;
  const stale = {
    id: 'row-1', ip: '192.0.2.55', scan_count: 3,
    vt_verdict: 'clean', vt_payload: { last_analysis_stats: { harmless: 90 } },
    last_scanned_at: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    first_scanned_at: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    corr_payload: { scoring: { version: 4 }, sources: [{ source: 'VirusTotal', verdict: 'clean' }] },
    corr_confidence: 0,
  };
  const supabase = {
    from() {
      const chain = {
        select() { return this; },
        eq() { return this; },
        maybeSingle: async () => ({ data: stale, error: null }),
        delete() { return { lt: async () => ({ error: null }) }; },
        update(payload) {
          updated = payload;
          return { eq: async () => ({ error: null }) };
        },
      };
      return chain;
    },
  };

  try {
    mockModule(modulePaths[0], { getSupabase: () => supabase });
    mockModule(modulePaths[1], { httpGet: async () => {
      vtCalls++;
      return { status: 200, data: { data: { attributes: {
        last_analysis_stats: { malicious: 12, suspicious: 2, harmless: 50, undetected: 20 },
        reputation: -20,
      } } } };
    } });
    mockModule(modulePaths[2], { requireAuth: () => true });
    mockModule(modulePaths[3], {
      getVtKeys: () => ['key'], getVtKeysForRequest: () => ['key'],
      getVtAvailableKeyCount: () => 1, getNextVtQuotaResetAt: () => null,
      getNextVtCooldownAt: () => null, markVtKeyRateLimited() {},
      markVtKeyQuotaExceeded() {}, shouldTryNextVtKey: () => false,
      isVtKeyQuotaExceeded: () => false, isVtTemporaryRateLimit: () => false,
      isVtQuotaExceeded: () => false, isVtBadKey: () => false,
    });
    mockModule(modulePaths[4], { logApiUsage: async () => {} });
    mockModule(modulePaths[5], { logIpScan: async () => {} });
    mockModule(modulePaths[6], { consumeScanBudget: () => true });
    delete require.cache[modulePaths[7]];
    const handler = require('./vt');
    const res = response();

    await handler({ method: 'GET', query: { ioc: '192.0.2.55' } }, res);

    assert.equal(vtCalls, 1);
    assert.equal(res.statusCode, 200);
    assert.equal(updated.vt_verdict, 'malicious');
    assert.equal(updated.scan_count, 4);
    assert.deepEqual(updated.corr_payload, {});
    assert.equal(updated.corr_confidence, null);
    assert.equal(res.body._meta.cache.scanCount, 4);
  } finally {
    for (const [path, entry] of originals) {
      if (entry) require.cache[path] = entry;
      else delete require.cache[path];
    }
  }
});
